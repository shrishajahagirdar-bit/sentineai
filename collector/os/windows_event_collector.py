"""
Windows Event Log Collector - Production OS Telemetry

Reads real Windows Security Event Log for authentication and process events.
Production-grade collector that replaces synthetic data with actual system logs.

Event IDs Collected:
- 4624: Successful logon (authentication success)
- 4625: Failed logon (authentication failure)
- 4634: User logoff (logout)
- 4647: User initiated logoff (logout)
- 4688: Process creation (new process started)
- 4689: Process termination (process ended)

Output Format:
{
    "source": "windows_event_log",
    "event_id": 4624,
    "user": "DOMAIN\\username",
    "host": "WORKSTATION-01",
    "timestamp": "2024-01-15T09:30:00Z",
    "process": "C:\\Windows\\System32\\cmd.exe",
    "ip_address": "192.168.1.100",
    "raw_event": "full event message...",
    "event_type": "auth | process | system",
    "logon_type": "Interactive | Network | etc.",
    "record_number": 12345,
    "metadata": {...}
}
"""

from __future__ import annotations

import socket
import time
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


# Windows Event ID mappings for OS telemetry
WINDOWS_EVENT_MAP = {
    # Authentication Events
    4624: {
        "category": "auth",
        "event_type": "login_success",
        "severity": "low",
        "description": "Successful logon",
        "fields": ["user", "host", "ip_address", "logon_type"]
    },
    4625: {
        "category": "auth",
        "event_type": "login_failure",
        "severity": "medium",
        "description": "Failed logon",
        "fields": ["user", "host", "ip_address", "failure_reason"]
    },
    4634: {
        "category": "auth",
        "event_type": "logout",
        "severity": "low",
        "description": "User logoff",
        "fields": ["user", "host"]
    },
    4647: {
        "category": "auth",
        "event_type": "user_initiated_logout",
        "severity": "low",
        "description": "User initiated logoff",
        "fields": ["user", "host"]
    },
    # Process Events
    4688: {
        "category": "process",
        "event_type": "process_creation",
        "severity": "low",
        "description": "A new process has been created",
        "fields": ["user", "host", "process", "parent_process", "command_line"]
    },
    4689: {
        "category": "process",
        "event_type": "process_termination",
        "severity": "low",
        "description": "A process has exited",
        "fields": ["user", "host", "process", "exit_code"]
    },
}


class WindowsEventCollector:
    """
    Production Windows Event Log Collector

    Reads real Windows Security Event Log for authentication and process events.
    Designed for continuous monitoring with duplicate prevention and error handling.

    Features:
    - Reads Security Event Log for auth events
    - Reads System Event Log for process events
    - Tracks last read record numbers to avoid duplicates
    - Graceful fallback if logs unavailable
    - User-mode only (no kernel drivers)
    - Safe error handling and logging
    """

    def __init__(self) -> None:
        self.hostname = socket.gethostname()
        self.state_file = CONFIG.event_log_state
        self.state = load_json(self.state_file, {})

        # Log names to monitor
        self.log_names = {
            "Security": "security_events",
            "System": "system_events",
        }

        # Validate pywin32 availability
        if win32evtlog is None:
            log_health_event(
                "warning",
                "windows_event_collector_init",
                "pywin32 not available; Windows Event Log collection disabled",
            )

    def collect_once(self, max_events: int = 100) -> list[dict[str, Any]]:
        """
        Collect events from Windows Event Logs once.

        Args:
            max_events: Maximum events to collect per log (prevents memory issues)

        Returns:
            List of normalized OS telemetry events
        """
        if win32evtlog is None:
            return []

        events: list[dict[str, Any]] = []

        for log_name, log_type in self.log_names.items():
            try:
                log_events = self._collect_from_log(log_name, log_type, max_events)
                events.extend(log_events)
            except Exception as exc:
                log_health_event(
                    "error",
                    "windows_event_collection",
                    f"Failed to collect from {log_name} log",
                    context={"log_name": log_name, "error": str(exc)},
                )

        # Update state with new record numbers
        save_json(self.state_file, self.state)

        return events

    def _collect_from_log(
        self, log_name: str, log_type: str, max_events: int
    ) -> list[dict[str, Any]]:
        """Collect events from a specific Windows Event Log."""
        events: list[dict[str, Any]] = []

        try:
            # Open event log
            handle = win32evtlog.OpenEventLog(None, log_name)

            # Get last processed record number
            last_record = int(self.state.get(log_name, 0))

            # Read events in reverse chronological order
            flags = (
                win32evtlog.EVENTLOG_BACKWARDS_READ
                | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            )

            collected = 0
            reached_known = False

            while collected < max_events and not reached_known:
                records = win32evtlog.ReadEventLog(handle, flags, 0)

                if not records:
                    break

                for record in records:
                    record_number = int(record.RecordNumber)

                    # Stop if we've reached previously processed records
                    if record_number <= last_record:
                        reached_known = True
                        break

                    # Parse the event
                    event = self._parse_event_record(record, log_name, log_type)
                    if event:
                        events.append(event)
                        collected += 1

                        if collected >= max_events:
                            break

            # Update state with highest record number seen
            if events:
                max_record = max(event["record_number"] for event in events)
                self.state[log_name] = max_record

        except Exception as exc:
            log_health_event(
                "warning",
                "windows_event_log_read",
                f"Error reading {log_name} log",
                context={"log_name": log_name, "error": str(exc)},
            )

        return events

    def _parse_event_record(
        self, record: Any, log_name: str, log_type: str
    ) -> dict[str, Any] | None:
        """
        Parse a Windows Event Log record into normalized telemetry format.

        Args:
            record: Windows Event Log record object
            log_name: Name of the log (Security, System, etc.)
            log_type: Type identifier for the log

        Returns:
            Normalized telemetry event or None if parsing fails
        """
        try:
            event_id = int(record.EventID & 0xFFFF)

            # Only process events we're interested in
            if event_id not in WINDOWS_EVENT_MAP:
                return None

            event_config = WINDOWS_EVENT_MAP[event_id]

            # Extract basic information
            timestamp = self._extract_timestamp(record)
            hostname = str(getattr(record, "ComputerName", self.hostname) or self.hostname)
            record_number = int(record.RecordNumber)

            # Extract event message
            message = self._extract_message(record, log_name)

            # Extract structured fields based on event type
            fields = self._extract_event_fields(event_id, record, message)

            # Build normalized telemetry event
            telemetry_event = {
                # Source identification
                "source": "windows_event_log",
                "log_name": log_name,
                "log_type": log_type,

                # Event classification
                "event_type": "os_telemetry",
                "category": event_config["category"],
                "sub_event_type": event_config["event_type"],
                "severity": event_config["severity"],

                # Event details
                "event_id": event_id,
                "record_number": record_number,
                "description": event_config["description"],

                # Temporal
                "timestamp": timestamp,

                # Identity and location
                "user": fields.get("user", "unknown"),
                "host": hostname,

                # Process information (if applicable)
                "process": fields.get("process"),
                "parent_process": fields.get("parent_process"),
                "command_line": fields.get("command_line"),

                # Network information (if applicable)
                "ip_address": fields.get("ip_address"),
                "logon_type": fields.get("logon_type"),

                # Raw data for debugging
                "raw_event": message[:2000],  # Truncate for storage

                # Risk assessment (initial)
                "risk_score": self._calculate_initial_risk(event_config, fields),

                # Metadata
                "metadata": {
                    "collector": "windows_event_collector",
                    "event_category": getattr(record, "EventCategory", None),
                    "source_name": getattr(record, "SourceName", ""),
                    "collected_at": datetime.now(timezone.utc).isoformat(),
                    "windows_event_id": event_id,
                },
            }

            return telemetry_event

        except Exception as exc:
            log_health_event(
                "debug",
                "windows_event_parsing",
                f"Failed to parse event record: {str(exc)}",
                context={"event_id": getattr(record, "EventID", "unknown")},
            )
            return None

    def _extract_timestamp(self, record: Any) -> str:
        """Extract timestamp from event record."""
        try:
            generated = getattr(record, "TimeGenerated", None)
            if generated:
                return generated.Format()
        except Exception:
            pass

        # Fallback to current time
        return datetime.now(timezone.utc).isoformat()

    def _extract_message(self, record: Any, log_name: str) -> str:
        """Extract human-readable message from event record."""
        try:
            if win32evtlogutil is not None:
                message = win32evtlogutil.SafeFormatMessage(record, log_name)
                if message:
                    return message
        except Exception:
            pass

        # Fallback to basic message
        return f"Windows Event ID {record.EventID}"

    def _extract_event_fields(
        self, event_id: int, record: Any, message: str
    ) -> dict[str, Any]:
        """
        Extract structured fields from event based on Event ID.

        Uses string inserts from Windows Event Log to parse specific fields.
        """
        fields = {}

        try:
            inserts = getattr(record, "StringInserts", None) or []

            if event_id == 4624:  # Successful logon
                if len(inserts) > 1:
                    fields["user"] = str(inserts[1]).strip()
                if len(inserts) > 8:
                    fields["logon_type"] = self._decode_logon_type(str(inserts[8]).strip())
                if len(inserts) > 18:
                    ip = str(inserts[18]).strip()
                    if ip and ip != "-":
                        fields["ip_address"] = ip

            elif event_id == 4625:  # Failed logon
                if len(inserts) > 5:
                    fields["user"] = str(inserts[5]).strip()
                if len(inserts) > 10:
                    fields["failure_reason"] = str(inserts[10]).strip()
                if len(inserts) > 19:
                    ip = str(inserts[19]).strip()
                    if ip and ip != "-":
                        fields["ip_address"] = ip

            elif event_id in (4634, 4647):  # Logoff events
                if len(inserts) > 1:
                    fields["user"] = str(inserts[1]).strip()

            elif event_id == 4688:  # Process creation
                if len(inserts) > 1:
                    fields["user"] = str(inserts[1]).strip()
                if len(inserts) > 5:
                    fields["process"] = str(inserts[5]).strip()
                if len(inserts) > 7:
                    fields["parent_process"] = str(inserts[7]).strip()
                if len(inserts) > 8:
                    fields["command_line"] = str(inserts[8]).strip()

            elif event_id == 4689:  # Process termination
                if len(inserts) > 1:
                    fields["user"] = str(inserts[1]).strip()
                if len(inserts) > 5:
                    fields["process"] = str(inserts[5]).strip()
                if len(inserts) > 6:
                    fields["exit_code"] = str(inserts[6]).strip()

        except Exception as exc:
            log_health_event(
                "debug",
                "windows_event_field_extraction",
                f"Failed to extract fields for event {event_id}: {str(exc)}",
            )

        return fields

    @staticmethod
    def _decode_logon_type(logon_type_code: str) -> str:
        """Decode Windows logon type code to human-readable string."""
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

    @staticmethod
    def _calculate_initial_risk(event_config: dict[str, Any], fields: dict[str, Any]) -> float:
        """
        Calculate initial risk score based on event characteristics.

        This provides a basic risk assessment before ML processing.
        Higher scores indicate potentially suspicious events.
        """
        risk_score = 0.0

        # Failed authentication is suspicious
        if event_config["event_type"] == "login_failure":
            risk_score += 0.3

        # Network logons from unknown IPs
        if fields.get("logon_type") == "Network":
            if not fields.get("ip_address") or fields.get("ip_address") == "unknown":
                risk_score += 0.2

        # Unusual logon types
        unusual_types = ["NetworkCleartext", "NewCredentials"]
        if fields.get("logon_type") in unusual_types:
            risk_score += 0.4

        return min(risk_score, 1.0)

    def get_status(self) -> dict[str, Any]:
        """Get collector status and statistics."""
        return {
            "collector": "windows_event_collector",
            "available": win32evtlog is not None,
            "logs_monitored": list(self.log_names.keys()),
            "last_records": self.state.copy(),
            "supported_events": list(WINDOWS_EVENT_MAP.keys()),
        }
