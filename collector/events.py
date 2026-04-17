from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from collector.storage import load_json, save_json
from sentinel_config import CONFIG

try:
    import win32evtlog  # type: ignore
    import win32evtlogutil  # type: ignore
except ImportError:  # pragma: no cover
    win32evtlog = None
    win32evtlogutil = None


SECURITY_EVENT_MAP = {
    4624: ("login_success", "Successful logon"),
    4625: ("login_failure", "Failed logon"),
    4634: ("logoff", "User logoff"),
    4672: ("privileged_logon", "Special privileges assigned"),
}


class WindowsEventCollector:
    def __init__(self) -> None:
        self.state = load_json(CONFIG.event_log_state, {})

    def collect(self) -> list[dict[str, Any]]:
        if win32evtlog is None:
            return [self._status_event("warning", "pywin32 is not installed; Windows Event Logs are unavailable.")]

        events: list[dict[str, Any]] = []
        new_state = dict(self.state)

        for log_name in CONFIG.event_logs:
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
                        channel_events.append(self._parse_event(log_name, record))

                    if reached_known_records:
                        break

                channel_events = sorted(channel_events, key=lambda item: item["record_number"])
                if channel_events:
                    new_state[log_name] = channel_events[-1]["record_number"]
                    events.extend(channel_events)
            except Exception as exc:
                events.append(self._status_event("warning", f"Unable to read {log_name} log: {exc}"))

        self.state = new_state
        save_json(CONFIG.event_log_state, new_state)
        return events

    def _parse_event(self, log_name: str, record: Any) -> dict[str, Any]:
        event_id = int(record.EventID & 0xFFFF)
        category, default_message = SECURITY_EVENT_MAP.get(event_id, ("windows_event", "Windows event"))
        username = None
        message = default_message

        try:
            if win32evtlogutil is not None:
                message = win32evtlogutil.SafeFormatMessage(record, log_name) or default_message
        except Exception:
            message = default_message

        inserts = getattr(record, "StringInserts", None) or []
        if inserts:
            username = str(inserts[5]) if len(inserts) > 5 else str(inserts[0])

        generated = getattr(record, "TimeGenerated", None)
        timestamp = generated.Format() if generated else datetime.now(timezone.utc).isoformat()

        return {
            "timestamp": timestamp,
            "source": "windows_event_log",
            "event_type": category,
            "record_number": int(record.RecordNumber),
            "log_name": log_name,
            "event_id": event_id,
            "host": getattr(record, "ComputerName", "localhost"),
            "user": username or "unknown",
            "message": message.strip().replace("\r", " ").replace("\n", " ")[:2000],
            "status": "ok",
            "raw": {"event_category": getattr(record, "EventCategory", None)},
        }

    @staticmethod
    def _status_event(level: str, message: str) -> dict[str, Any]:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "windows_event_log",
            "event_type": "collector_status",
            "status": level,
            "message": message,
            "user": "system",
        }
