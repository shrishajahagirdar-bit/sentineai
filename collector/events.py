from __future__ import annotations

import platform
import re
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from collector.storage import load_json, save_json
from core.safe_wrapper import log_health_event
from sentinel_config import CONFIG

try:
    import win32evtlog  # type: ignore
    import win32evtlogutil  # type: ignore
except ImportError:  # pragma: no cover
    win32evtlog = None
    win32evtlogutil = None


SECURITY_EVENT_MAP = {
    4624: ("auth", "login_success", "low", "Successful logon"),
    4625: ("auth", "login_failure", "high", "Failed logon"),
    4634: ("auth", "logout", "low", "User logoff"),
    4647: ("auth", "logout", "low", "User initiated logoff"),
    4672: ("auth", "privilege_change", "medium", "Special privileges assigned"),
    4688: ("process", "process_creation", "medium", "A new process has been created"),
}

SYSMON_EVENT_MAP = {
    1: ("process", "process_creation", "medium", "Sysmon process create"),
    3: ("network", "network_connection", "medium", "Sysmon network connection"),
    5: ("process", "process_termination", "low", "Sysmon process termination"),
}


class WindowsEventCollector:
    def __init__(self) -> None:
        self.state = load_json(CONFIG.event_log_state, {})
        self.hostname = socket.gethostname()

    def collect(self) -> list[dict[str, Any]]:
        if CONFIG.os_platform == "windows":
            return self._collect_windows()
        return self._collect_linux()

    def _collect_windows(self) -> list[dict[str, Any]]:
        if win32evtlog is None:
            log_health_event(
                "warning",
                "windows_event_log",
                "pywin32 is not installed; Windows Event Logs are unavailable.",
            )
            return []

        events: list[dict[str, Any]] = []
        new_state = dict(self.state)
        log_names = list(CONFIG.event_logs)
        if CONFIG.enable_sysmon:
            log_names.append(CONFIG.sysmon_log_name)

        for log_name in log_names:
            try:
                handle = win32evtlog.OpenEventLog(None, log_name)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                last_seen = int(self.state.get(log_name, 0))
                channel_events: list[dict[str, Any]] = []
                reached_known_records = False

                while True:
                    records = win32evtlog.ReadEventLog(handle, flags, 0)
                    if not records:
                        break

                    for record in records:
                        record_number = int(record.RecordNumber)
                        if record_number <= last_seen:
                            reached_known_records = True
                            break
                        parsed = self._parse_windows_event(log_name, record)
                        if parsed is not None:
                            channel_events.append(parsed)
                        if len(channel_events) >= CONFIG.max_eventlog_records_per_cycle:
                            reached_known_records = True
                            break

                    if reached_known_records:
                        break

                channel_events = sorted(channel_events, key=lambda item: item["record_number"])
                if channel_events:
                    new_state[log_name] = channel_events[-1]["record_number"]
                    events.extend(channel_events)
            except Exception as exc:
                log_health_event(
                    "warning",
                    "windows_event_log",
                    f"Unable to read {log_name} log.",
                    context={"log_name": log_name, "error": str(exc)},
                )

        self.state = new_state
        save_json(CONFIG.event_log_state, new_state)
        return events

    def _parse_windows_event(self, log_name: str, record: Any) -> dict[str, Any] | None:
        event_id = int(record.EventID & 0xFFFF)
        if log_name == CONFIG.sysmon_log_name:
            mapping = SYSMON_EVENT_MAP
            default = ("system", "sysmon_event", "low", "Sysmon event")
        else:
            mapping = SECURITY_EVENT_MAP
            default = ("system", "windows_event", "low", "Windows event")

        source, category, severity, default_message = mapping.get(event_id, default)
        username = None
        message = default_message

        try:
            if win32evtlogutil is not None:
                message = win32evtlogutil.SafeFormatMessage(record, log_name) or default_message
        except Exception:
            message = default_message

        inserts = getattr(record, "StringInserts", None) or []
        if inserts:
            username = self._extract_username(event_id, inserts)

        generated = getattr(record, "TimeGenerated", None)
        timestamp = generated.Format() if generated else datetime.now(timezone.utc).isoformat()
        parsed_fields = self._parse_insert_fields(log_name, event_id, inserts)
        hostname = str(getattr(record, "ComputerName", self.hostname) or self.hostname)

        if event_id not in mapping and source == "system":
            return None

        return {
            "timestamp": timestamp,
            "hostname": hostname,
            "source": source,
            "event_type": category,
            "severity": severity,
            "record_number": int(record.RecordNumber),
            "log_name": log_name,
            "host": hostname,
            "user": username or "unknown",
            "message": message.strip().replace("\r", " ").replace("\n", " ")[:2000],
            "status": "ok",
            "raw_log": message.strip().replace("\r", " ").replace("\n", " ")[:2000],
            "parsed_fields": {
                **parsed_fields,
                "windows_event_id": event_id,
                "record_number": int(record.RecordNumber),
            },
            "metadata": {
                "collector": "windows_event_log",
                "event_category": getattr(record, "EventCategory", None),
                "log_name": log_name,
                "windows_event_id": event_id,
            },
        }

    def _collect_linux(self) -> list[dict[str, Any]]:
        state = load_json(CONFIG.linux_log_state, {})
        events: list[dict[str, Any]] = []
        for path in [CONFIG.linux_auth_log, CONFIG.linux_secure_log, CONFIG.linux_syslog]:
            if path.exists():
                events.extend(self._read_linux_log(path, state))
        events.extend(self._read_journalctl(state))
        save_json(CONFIG.linux_log_state, state)
        return events

    def _read_linux_log(self, path: Path, state: dict[str, Any]) -> list[dict[str, Any]]:
        key = str(path)
        last_offset = int(state.get(key, 0) or 0)
        events: list[dict[str, Any]] = []
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                handle.seek(last_offset)
                while True:
                    line = handle.readline()
                    if not line:
                        break
                    parsed = self._parse_linux_line(path.name, line.strip())
                    if parsed is not None:
                        events.append(parsed)
                state[key] = handle.tell()
        except OSError as exc:
            log_health_event(
                "warning",
                "linux_log_reader",
                "Unable to read Linux log.",
                context={"path": str(path), "error": str(exc)},
            )
        return events

    def _read_journalctl(self, state: dict[str, Any]) -> list[dict[str, Any]]:
        since = str(state.get("journalctl_since", "10 seconds ago"))
        try:
            result = subprocess.run(
                ["journalctl", "--since", since, "-n", str(CONFIG.linux_journalctl_lines), "-o", "short-iso"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
        except Exception:
            return []

        if result.returncode != 0:
            return []

        events: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            parsed = self._parse_linux_line("journald", line.strip())
            if parsed is not None:
                events.append(parsed)
        state["journalctl_since"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        return events

    def _parse_linux_line(self, source_name: str, line: str) -> dict[str, Any] | None:
        if not line:
            return None

        lowered = line.lower()
        if "failed password" in lowered or "authentication failure" in lowered:
            event_type = "login_failure"
            severity = "high"
            source = "auth"
        elif "session opened" in lowered or "accepted password" in lowered:
            event_type = "login_success"
            severity = "low"
            source = "auth"
        elif "session closed" in lowered:
            event_type = "logout"
            severity = "low"
            source = "auth"
        elif "sudo" in lowered or "privilege" in lowered:
            event_type = "privilege_change"
            severity = "medium"
            source = "auth"
        else:
            return None

        username = "unknown"
        user_match = re.search(r"for (invalid user )?([A-Za-z0-9_.-]+)", line)
        if user_match:
            username = user_match.group(2)
        elif "sudo:" in lowered:
            sudo_match = re.search(r"sudo:\s+([A-Za-z0-9_.-]+)", line)
            if sudo_match:
                username = sudo_match.group(1)

        ip_match = re.search(r"from ([0-9a-fA-F:.]+)", line)
        remote_ip = ip_match.group(1) if ip_match else ""
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hostname": self.hostname,
            "source": source,
            "event_type": event_type,
            "severity": severity,
            "status": "ok",
            "user": username,
            "raw_log": line[:2000],
            "message": line[:2000],
            "parsed_fields": {
                "remote_ip": remote_ip,
                "log_source": source_name,
            },
            "metadata": {
                "collector": "linux_log_reader",
                "log_source": source_name,
                "platform": platform.system().lower(),
            },
        }

    @staticmethod
    def _extract_username(event_id: int, inserts: list[Any]) -> str | None:
        if event_id in {4624, 4625}:
            return str(inserts[5]) if len(inserts) > 5 else None
        if event_id in {4634, 4647, 4672}:
            return str(inserts[1]) if len(inserts) > 1 else None
        if event_id == 4688:
            return str(inserts[1]) if len(inserts) > 1 else None
        return str(inserts[0]) if inserts else None

    @staticmethod
    def _parse_insert_fields(log_name: str, event_id: int, inserts: list[Any]) -> dict[str, Any]:
        fields: dict[str, Any] = {}
        if event_id in {4624, 4625}:
            if len(inserts) > 18:
                fields["logon_type"] = str(inserts[8])
                fields["workstation"] = str(inserts[11])
                fields["source_ip"] = str(inserts[19]) if len(inserts) > 19 else ""
            fields["auth_package"] = str(inserts[10]) if len(inserts) > 10 else ""
        elif event_id in {4634, 4647}:
            fields["session_event"] = "logout"
        elif event_id == 4672:
            fields["privilege_change"] = True
        elif event_id == 4688:
            fields["new_process_name"] = str(inserts[5]) if len(inserts) > 5 else ""
            fields["creator_process_name"] = str(inserts[13]) if len(inserts) > 13 else ""
            fields["command_line"] = str(inserts[8]) if len(inserts) > 8 else ""
        elif log_name == CONFIG.sysmon_log_name and event_id == 1:
            fields["sysmon_process_create"] = True
        elif log_name == CONFIG.sysmon_log_name and event_id == 3:
            fields["sysmon_network_connection"] = True
        return fields
