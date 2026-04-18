from __future__ import annotations

import json
import queue
import threading
from datetime import datetime, timezone
from typing import Any

from agent.core.config import AgentConfig
from agent.core.normalizer import build_event

try:
    import win32evtlog  # type: ignore
    import win32evtlogutil  # type: ignore
except ImportError:  # pragma: no cover
    win32evtlog = None
    win32evtlogutil = None


WINDOWS_EVENT_MAP: dict[int, tuple[str, str, str]] = {
    4624: ("login", "low", "Successful logon"),
    4625: ("login_failure", "high", "Failed logon"),
    4634: ("logout", "low", "User logoff"),
    4647: ("logout", "low", "User initiated logoff"),
    4672: ("privilege_escalation_attempt", "high", "Special privileges assigned"),
    4688: ("process_create", "medium", "Process creation"),
    7036: ("service_state_change", "medium", "Service started or stopped"),
    7034: ("system_event", "high", "Service terminated unexpectedly"),
    1000: ("application_crash", "high", "Application error"),
}


class WindowsEventCollector(threading.Thread):
    def __init__(
        self,
        config: AgentConfig,
        output_queue: "queue.Queue[dict[str, Any]]",
        logger: Any,
        stop_event: threading.Event,
    ) -> None:
        super().__init__(name="windows-event-collector", daemon=True)
        self.config = config
        self.output_queue = output_queue
        self.logger = logger
        self.stop_event = stop_event
        self.state = self._load_state()
        self.log_names = ["Security", "System", "Application"]
        if self.config.enable_sysmon:
            self.log_names.append("Microsoft-Windows-Sysmon/Operational")

    def run(self) -> None:
        while not self.stop_event.is_set():
            self._collect_cycle()
            self.stop_event.wait(self.config.event_poll_seconds)

    def _collect_cycle(self) -> None:
        if win32evtlog is None:
            return

        next_state = dict(self.state)
        for log_name in self.log_names:
            try:
                handle = win32evtlog.OpenEventLog(None, log_name)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                last_seen = int(self.state.get(log_name, 0) or 0)
                latest_seen = last_seen
                reached_known = False

                while not reached_known:
                    records = win32evtlog.ReadEventLog(handle, flags, 0)
                    if not records:
                        break
                    for record in records:
                        record_number = int(record.RecordNumber)
                        if record_number <= last_seen:
                            reached_known = True
                            break
                        latest_seen = max(latest_seen, record_number)
                        event = self._parse_record(log_name, record)
                        if event is not None:
                            self._put(event)

                if latest_seen > last_seen:
                    next_state[log_name] = latest_seen
            except Exception as exc:
                self.logger.warning(
                    "windows event collection warning",
                    extra={"payload": {"collector": "windows_event", "log_name": log_name, "error": str(exc)}},
                )

        self.state = next_state
        self._save_state(next_state)

    def _parse_record(self, log_name: str, record: Any) -> dict[str, Any] | None:
        windows_event_id = int(record.EventID & 0xFFFF)
        mapping = WINDOWS_EVENT_MAP.get(windows_event_id)
        if mapping is None and log_name != "Microsoft-Windows-Sysmon/Operational":
            return None

        event_type, severity, default_message = mapping or ("system_event", "medium", "Sysmon event")
        inserts = getattr(record, "StringInserts", None) or []
        user = self._extract_user(windows_event_id, inserts)
        message = default_message

        try:
            if win32evtlogutil is not None:
                message = win32evtlogutil.SafeFormatMessage(record, log_name) or default_message
        except Exception:
            message = default_message

        generated = getattr(record, "TimeGenerated", None)
        timestamp = generated.Format() if generated else datetime.now(timezone.utc).isoformat()
        raw_data = {
            "log_name": log_name,
            "windows_event_id": windows_event_id,
            "record_number": int(record.RecordNumber),
            "message": message.strip().replace("\r", " ").replace("\n", " ")[:2000],
            "inserts": [str(item) for item in inserts[:20]],
        }

        pid = 0
        process_name = ""
        if windows_event_id == 4688 and len(inserts) > 5:
            process_name = str(inserts[5])

        return build_event(
            self.config,
            user=user,
            event_source="windows_event",
            event_type=event_type,
            severity=severity,
            raw_data=raw_data,
            process_name=process_name,
            pid=pid,
            event_log_id=f"{log_name}:{record.RecordNumber}:{windows_event_id}",
            timestamp=timestamp,
        )

    def _extract_user(self, windows_event_id: int, inserts: list[Any]) -> str:
        try:
            if windows_event_id in {4624, 4625} and len(inserts) > 5:
                return str(inserts[5])
            if windows_event_id in {4634, 4647, 4672} and len(inserts) > 1:
                return str(inserts[1])
            if windows_event_id == 4688 and len(inserts) > 1:
                return str(inserts[1])
        except Exception:
            return "unknown"
        return "unknown"

    def _put(self, event: dict[str, Any]) -> None:
        try:
            self.output_queue.put_nowait(event)
        except queue.Full:
            self.logger.warning("agent queue full", extra={"payload": {"collector": "windows_event", "event_type": event.get("event_type")}})

    def _load_state(self) -> dict[str, int]:
        try:
            if self.config.event_state_path.exists():
                return json.loads(self.config.event_state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
        return {}

    def _save_state(self, state: dict[str, int]) -> None:
        try:
            self.config.event_state_path.parent.mkdir(parents=True, exist_ok=True)
            self.config.event_state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
        except OSError:
            return
