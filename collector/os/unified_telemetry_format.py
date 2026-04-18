"""
Unified Telemetry Format - OS Telemetry Normalization

Normalizes all OS telemetry events into a consistent format for downstream processing.
Ensures compatibility with existing SentinelAI pipeline components.

Supported Event Types:
- Windows Event Log events (auth, process, security)
- Process lifecycle events (creation, termination, spikes)
- System telemetry events

Output Format:
{
    "event_type": "os_telemetry",
    "category": "auth | process | security | system",
    "sub_event_type": "login_success | process_creation | etc",
    "user": "DOMAIN\\username",
    "host": "WORKSTATION-01",
    "timestamp": "2024-01-15T09:30:00Z",
    "process": "C:\\Windows\\System32\\cmd.exe",
    "pid": 1234,
    "parent_pid": 567,
    "risk_score": 0.0-1.0,
    "metadata": {...},
    "raw_data": {...}
}
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict

from core.safe_wrapper import log_health_event


class UnifiedTelemetryFormat:
    """
    Normalizes OS telemetry events into unified format.

    Ensures all telemetry events follow the same structure and field naming
    conventions for consistent processing by ML engines, UEBA, and dashboards.

    Features:
    - Field normalization and validation
    - Risk score calculation
    - Metadata enrichment
    - Type safety and error handling
    """

    # Event type mappings
    EVENT_TYPE_MAPPINGS = {
        # Windows Event Log events
        "win_event": "os_telemetry",
        "event_log": "os_telemetry",

        # Process events
        "process_creation": "os_telemetry",
        "process_termination": "os_telemetry",
        "cpu_spike": "os_telemetry",
        "memory_spike": "os_telemetry",

        # System events
        "system_event": "os_telemetry",
    }

    # Category mappings
    CATEGORY_MAPPINGS = {
        # Event Log categories
        4624: "auth",  # Logon success
        4625: "auth",  # Logon failure
        4634: "auth",  # Logoff
        4688: "process",  # Process creation
        4689: "process",  # Process termination
        4720: "user_management",  # User account created
        4722: "user_management",  # User account enabled
        4725: "user_management",  # User account disabled
        4726: "user_management",  # User account deleted
        4738: "group_management",  # User added to group
        4740: "group_management",  # User removed from group
        4768: "kerberos",  # Kerberos TGT requested
        4769: "kerberos",  # Kerberos service ticket requested
        4771: "kerberos",  # Kerberos pre-auth failed
        4776: "ntlm",  # NTLM auth attempt
        4778: "session",  # RDP session reconnected
        4779: "session",  # RDP session disconnected

        # Process monitor categories
        "process_creation": "process",
        "process_termination": "process",
        "cpu_spike": "process",
        "memory_spike": "process",
    }

    # Sub-event type mappings
    SUB_EVENT_MAPPINGS = {
        4624: "login_success",
        4625: "login_failure",
        4634: "logout",
        4688: "process_creation",
        4689: "process_termination",
        4720: "user_created",
        4722: "user_enabled",
        4725: "user_disabled",
        4726: "user_deleted",
        4738: "user_added_to_group",
        4740: "user_removed_from_group",
        4768: "kerberos_tgt_request",
        4769: "kerberos_service_ticket",
        4771: "kerberos_pre_auth_failed",
        4776: "ntlm_auth_attempt",
        4778: "rdp_reconnect",
        4779: "rdp_disconnect",
    }

    @classmethod
    def normalize_event(cls, raw_event: dict[str, Any]) -> dict[str, Any] | None:
        """
        Normalize a raw telemetry event into unified format.

        Args:
            raw_event: Raw event from collector

        Returns:
            Normalized event dict or None if invalid
        """
        try:
            # Determine event type and category
            event_type = cls._determine_event_type(raw_event)
            category = cls._determine_category(raw_event)
            sub_event_type = cls._determine_sub_event_type(raw_event)

            # Build normalized event
            normalized = {
                # Event classification
                "event_type": event_type,
                "category": category,
                "sub_event_type": sub_event_type,
                "severity": cls._determine_severity(raw_event),

                # Identity and location
                "user": cls._normalize_user(raw_event.get("user", raw_event.get("username", "unknown"))),
                "host": cls._normalize_host(raw_event.get("host", raw_event.get("hostname", "localhost"))),

                # Temporal
                "timestamp": cls._normalize_timestamp(raw_event.get("timestamp")),

                # Process information (if applicable)
                "process": raw_event.get("process", raw_event.get("process_name", "")),
                "pid": raw_event.get("pid"),
                "parent_pid": raw_event.get("parent_pid"),
                "command_line": raw_event.get("command_line", ""),

                # Resource usage (if applicable)
                "cpu_percent": raw_event.get("cpu_percent"),
                "memory_mb": raw_event.get("memory_mb"),

                # Risk assessment
                "risk_score": cls._calculate_risk_score(raw_event),

                # Source information
                "source": raw_event.get("source", "os_collector"),
                "collector": raw_event.get("collector", "unknown"),

                # Metadata
                "metadata": cls._build_metadata(raw_event),

                # Raw data for debugging/analysis
                "raw_data": raw_event.copy(),
            }

            # Remove None values for cleaner output
            normalized = {k: v for k, v in normalized.items() if v is not None}

            return normalized

        except Exception as exc:
            log_health_event(
                "warning",
                "telemetry_normalization_error",
                f"Failed to normalize event: {str(exc)} | Event: {raw_event.get('event_id', 'unknown')}",
            )
            return None

    @classmethod
    def normalize_events(cls, raw_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Normalize a list of raw telemetry events.

        Args:
            raw_events: List of raw events

        Returns:
            List of normalized events (invalid events filtered out)
        """
        normalized_events = []

        for raw_event in raw_events:
            normalized = cls.normalize_event(raw_event)
            if normalized:
                normalized_events.append(normalized)

        return normalized_events

    @classmethod
    def _determine_event_type(cls, event: dict[str, Any]) -> str:
        """Determine the event type."""
        # Check explicit event_type first
        if "event_type" in event:
            return cls.EVENT_TYPE_MAPPINGS.get(event["event_type"], event["event_type"])

        # Check for Windows Event Log
        if "event_id" in event or "event_record_id" in event:
            return "os_telemetry"

        # Check for process events
        if event.get("category") == "process":
            return "os_telemetry"

        # Default
        return "os_telemetry"

    @classmethod
    def _determine_category(cls, event: dict[str, Any]) -> str:
        """Determine the event category."""
        # Check explicit category
        if "category" in event:
            return event["category"]

        # Check Event ID mapping
        event_id = event.get("event_id")
        if event_id and event_id in cls.CATEGORY_MAPPINGS:
            return cls.CATEGORY_MAPPINGS[event_id]

        # Check sub_event_type
        sub_type = event.get("sub_event_type")
        if sub_type and sub_type in cls.CATEGORY_MAPPINGS:
            return cls.CATEGORY_MAPPINGS[sub_type]

        # Default based on content
        if "process" in event or "pid" in event:
            return "process"
        elif "user" in event or "username" in event:
            return "auth"
        else:
            return "system"

    @classmethod
    def _determine_sub_event_type(cls, event: dict[str, Any]) -> str:
        """Determine the sub-event type."""
        # Check explicit sub_event_type
        if "sub_event_type" in event:
            return event["sub_event_type"]

        # Check Event ID mapping
        event_id = event.get("event_id")
        if event_id and event_id in cls.SUB_EVENT_MAPPINGS:
            return cls.SUB_EVENT_MAPPINGS[event_id]

        # Default to category
        return event.get("category", "unknown")

    @classmethod
    def _determine_severity(cls, event: dict[str, Any]) -> str:
        """Determine event severity."""
        # Check explicit severity
        if "severity" in event:
            return event["severity"]

        # Determine based on risk score
        risk_score = cls._calculate_risk_score(event)
        if risk_score > 0.7:
            return "high"
        elif risk_score > 0.4:
            return "medium"
        else:
            return "low"

    @classmethod
    def _normalize_user(cls, user: str) -> str:
        """Normalize user field."""
        if not user or user == "unknown":
            return "unknown"

        # Clean up domain\user format
        user = user.strip()
        if "\\" in user:
            domain, username = user.split("\\", 1)
            return f"{domain.upper()}\\{username}"

        return user

    @classmethod
    def _normalize_host(cls, host: str) -> str:
        """Normalize host field."""
        if not host or host == "localhost":
            return "localhost"

        return host.upper().strip()

    @classmethod
    def _normalize_timestamp(cls, timestamp: str | None) -> str:
        """Normalize timestamp to ISO format."""
        if not timestamp:
            return datetime.now(timezone.utc).isoformat()

        # If already ISO format, return as-is
        if isinstance(timestamp, str) and "T" in timestamp:
            return timestamp

        # Try to parse and convert
        try:
            if isinstance(timestamp, str):
                # Handle common formats
                for fmt in ["%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%m/%d/%Y %H:%M:%S"]:
                    try:
                        dt = datetime.strptime(timestamp, fmt)
                        return dt.replace(tzinfo=timezone.utc).isoformat()
                    except ValueError:
                        continue

            # If all parsing fails, use current time
            return datetime.now(timezone.utc).isoformat()

        except Exception:
            return datetime.now(timezone.utc).isoformat()

    @classmethod
    def _calculate_risk_score(cls, event: dict[str, Any]) -> float:
        """Calculate risk score for the event."""
        # Use existing risk score if present
        if "risk_score" in event:
            return float(event["risk_score"])

        risk_score = 0.0

        # Auth failures are high risk
        if event.get("sub_event_type") == "login_failure":
            risk_score += 0.8

        # Process creation from suspicious executables
        process = event.get("process", "").lower()
        suspicious_procs = ["cmd.exe", "powershell.exe", "rundll32.exe", "regsvr32.exe"]
        if any(proc in process for proc in suspicious_procs):
            risk_score += 0.4

        # High CPU usage
        cpu_percent = event.get("cpu_percent", 0.0)
        if cpu_percent > 80.0:
            risk_score += 0.3

        # High memory usage
        memory_mb = event.get("memory_mb", 0.0)
        if memory_mb > 500.0:
            risk_score += 0.2

        # Unknown users
        user = event.get("user", "").lower()
        if user in ["unknown", "system", "local service", "network service"]:
            risk_score += 0.1

        return min(risk_score, 1.0)

    @classmethod
    def _build_metadata(cls, event: dict[str, Any]) -> dict[str, Any]:
        """Build metadata dictionary."""
        metadata = {
            "normalized_at": datetime.now(timezone.utc).isoformat(),
            "normalizer_version": "1.0",
        }

        # Add source-specific metadata
        if "event_record_id" in event:
            metadata["event_record_id"] = event["event_record_id"]

        if "log_name" in event:
            metadata["log_name"] = event["log_name"]

        if "source" in event:
            metadata["original_source"] = event["source"]

        return metadata

    @classmethod
    def validate_normalized_event(cls, event: dict[str, Any]) -> bool:
        """
        Validate that a normalized event has required fields.

        Args:
            event: Normalized event dict

        Returns:
            True if valid, False otherwise
        """
        required_fields = ["event_type", "category", "timestamp"]

        for field in required_fields:
            if field not in event or event[field] is None:
                return False

        # Validate timestamp format
        try:
            datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return False

        return True

    @classmethod
    def get_schema(cls) -> dict[str, Any]:
        """Get the schema definition for normalized events."""
        return {
            "type": "object",
            "properties": {
                "event_type": {"type": "string", "enum": ["os_telemetry"]},
                "category": {"type": "string", "enum": ["auth", "process", "security", "system", "user_management", "group_management", "kerberos", "ntlm", "session"]},
                "sub_event_type": {"type": "string"},
                "severity": {"type": "string", "enum": ["low", "medium", "high"]},
                "user": {"type": "string"},
                "host": {"type": "string"},
                "timestamp": {"type": "string", "format": "date-time"},
                "process": {"type": "string"},
                "pid": {"type": ["integer", "null"]},
                "parent_pid": {"type": ["integer", "null"]},
                "command_line": {"type": "string"},
                "cpu_percent": {"type": ["number", "null"]},
                "memory_mb": {"type": ["number", "null"]},
                "risk_score": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                "source": {"type": "string"},
                "collector": {"type": "string"},
                "metadata": {"type": "object"},
                "raw_data": {"type": "object"},
            },
            "required": ["event_type", "category", "timestamp"],
        }
