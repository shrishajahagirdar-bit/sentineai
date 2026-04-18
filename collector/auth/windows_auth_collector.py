"""
Windows Authentication Event Collector

Specialized collector for Windows Security Event Log authentication events.
Only processes authentication-related events (4624, 4625, 4634) for UEBA.

Design:
- Reads Windows Security Event Log using win32evtlog
- Extracts structured authentication telemetry
- Outputs canonicalized identity events
- Used exclusively for UEBA baseline building
"""

from __future__ import annotations

import socket
from datetime import datetime, timezone
from typing import Any

from core.safe_wrapper import log_health_event
from collector.storage import load_json, save_json
from sentinel_config import CONFIG

try:
    import win32evtlog  # type: ignore
    import win32evtlogutil  # type: ignore
except ImportError:  # pragma: no cover
    win32evtlog = None
    win32evtlogutil = None


# Windows authentication event IDs for UEBA
AUTH_EVENT_IDS = {
    4624: "login_success",      # Successful logon
    4625: "login_failure",      # Failed logon
    4634: "logout_event",       # User logoff
    4647: "user_initiated_logout",  # User initiated logoff
}


class WindowsAuthCollector:
    """
    Specialized collector for Windows authentication events.
    
    This collector extracts authentication telemetry specifically for UEBA
    processing. It reads Windows Security Event Log and extracts:
    - Event ID (4624, 4625, 4634)
    - Username
    - Hostname (source device)
    - Timestamp
    - IP address (logon IP)
    - Logon type (interactive, network, etc.)
    
    Output is in canonical identity event format, ready for UEBA transformer.
    """

    def __init__(self) -> None:
        self.hostname = socket.gethostname()
        self.state = load_json(CONFIG.event_log_state, {})
        self.auth_log_key = "Security"

    def collect(self) -> list[dict[str, Any]]:
        """
        Collect authentication events from Windows Security Log.
        
        Returns:
            List of canonical authentication events.
        """
        if CONFIG.os_platform != "windows" or win32evtlog is None:
            return []

        return self._collect_windows_auth_events()

    def _collect_windows_auth_events(self) -> list[dict[str, Any]]:
        """Read Windows Security Event Log for authentication events."""
        events: list[dict[str, Any]] = []
        new_state = dict(self.state)

        try:
            handle = win32evtlog.OpenEventLog(None, self.auth_log_key)
            flags = (
                win32evtlog.EVENTLOG_BACKWARDS_READ
                | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            )
            last_seen = int(self.state.get(self.auth_log_key, 0))
            auth_events: list[dict[str, Any]] = []
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

                    event_id = int(record.EventID & 0xFFFF)
                    
                    # Only process authentication events
                    if event_id not in AUTH_EVENT_IDS:
                        continue

                    parsed = self._parse_auth_event(record, event_id)
                    if parsed is not None:
                        auth_events.append(parsed)

                    if len(auth_events) >= CONFIG.max_eventlog_records_per_cycle:
                        reached_known_records = True
                        break

                if reached_known_records:
                    break

            # Sort by record number and update state
            auth_events = sorted(auth_events, key=lambda item: item["record_number"])
            if auth_events:
                new_state[self.auth_log_key] = auth_events[-1]["record_number"]
                events.extend(auth_events)

        except Exception as exc:
            log_health_event(
                "warning",
                "windows_auth_collector",
                f"Unable to read Windows Security Log: {str(exc)}",
                context={"error": str(exc)},
            )

        self.state = new_state
        save_json(CONFIG.event_log_state, new_state)
        return events

    def _parse_auth_event(
        self, record: Any, event_id: int
    ) -> dict[str, Any] | None:
        """
        Parse Windows authentication event record.
        
        Extracts:
        - Username
        - Hostname (source)
        - IP address (source IP for network logons)
        - Logon type (e.g., Network, Interactive, Service)
        - Timestamp
        
        Returns:
            Canonical identity event or None if unparseable
        """
        try:
            event_type = AUTH_EVENT_IDS.get(event_id, "unknown_auth")
            inserts = getattr(record, "StringInserts", None) or []
            
            # Parse Windows event string inserts
            username = self._extract_username(event_id, inserts)
            ip_address = self._extract_ip_address(event_id, inserts)
            logon_type = self._extract_logon_type(event_id, inserts)
            
            # Get timestamp
            generated = getattr(record, "TimeGenerated", None)
            timestamp = (
                generated.Format()
                if generated
                else datetime.now(timezone.utc).isoformat()
            )
            
            hostname = str(
                getattr(record, "ComputerName", self.hostname) or self.hostname
            )
            
            # Skip events with unknown users
            if username is None or username == "unknown" or username == "-":
                return None
            
            # Construct canonical identity event
            return {
                "event_type": "auth_event",
                "event_id": event_id,
                "auth_event_type": event_type,
                "user": username,
                "host": hostname,
                "source_device": hostname,
                "timestamp": timestamp,
                "ip_address": ip_address or "unknown",
                "logon_type": logon_type or "unknown",
                "raw_source": "windows_security",
                "record_number": int(record.RecordNumber),
                "source": "windows_auth",
                "status": "ok",
                "log_name": self.auth_log_key,
                "parsed_fields": {
                    "windows_event_id": event_id,
                    "record_number": int(record.RecordNumber),
                },
            }

        except Exception as exc:
            log_health_event(
                "debug",
                "windows_auth_parser",
                f"Failed to parse auth event: {str(exc)}",
            )
            return None

    @staticmethod
    def _extract_username(event_id: int, inserts: list[str]) -> str | None:
        """Extract username from event string inserts."""
        if not inserts:
            return None

        # String insert position varies by event ID
        # Event 4624: inserts[1] = TargetUserName
        # Event 4625: inserts[5] = TargetUserName
        # Event 4634: inserts[1] = TargetUserName
        
        try:
            if event_id == 4624:  # Logon Success
                return str(inserts[1]).strip() if len(inserts) > 1 else None
            elif event_id == 4625:  # Logon Failure
                return str(inserts[5]).strip() if len(inserts) > 5 else None
            elif event_id in (4634, 4647):  # Logoff
                return str(inserts[1]).strip() if len(inserts) > 1 else None
        except (IndexError, AttributeError):
            pass

        return None

    @staticmethod
    def _extract_ip_address(event_id: int, inserts: list[str]) -> str | None:
        """Extract source IP address from event string inserts."""
        if not inserts:
            return None

        try:
            # Event 4624: inserts[18] = SourceNetworkAddress
            if event_id == 4624 and len(inserts) > 18:
                ip = str(inserts[18]).strip()
                if ip and ip != "-" and ip != "::":
                    return ip
            # Event 4625: inserts[19] = SourceNetworkAddress
            elif event_id == 4625 and len(inserts) > 19:
                ip = str(inserts[19]).strip()
                if ip and ip != "-" and ip != "::":
                    return ip
        except (IndexError, AttributeError):
            pass

        return None

    @staticmethod
    def _extract_logon_type(event_id: int, inserts: list[str]) -> str | None:
        """Extract logon type from event string inserts."""
        if not inserts:
            return None

        try:
            # Event 4624: inserts[10] = LogonType
            if event_id == 4624 and len(inserts) > 10:
                logon_type_code = str(inserts[10]).strip()
                logon_types = {
                    "2": "Interactive",
                    "3": "Network",
                    "4": "Batch",
                    "5": "Service",
                    "7": "Unlock",
                    "8": "NetworkCleartext",
                    "9": "NewCredentials",
                    "10": "RemoteInteractive",
                    "11": "CachedInteractive",
                }
                return logon_types.get(logon_type_code, f"Type_{logon_type_code}")
        except (IndexError, AttributeError):
            pass

        return None
