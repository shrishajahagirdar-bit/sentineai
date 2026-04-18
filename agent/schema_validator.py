"""
Schema Validator for Windows Telemetry Events

Validates Windows telemetry events against the required schema.
Ensures data integrity and consistency for downstream processing.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from agent.core.logging import configure_logger


class WindowsTelemetrySchemaValidator:
    """
    Validates Windows telemetry events against schema requirements.

    Ensures events conform to the expected structure and data types
    before being sent to Kafka or processed by the pipeline.
    """

    # Required fields for all events
    REQUIRED_FIELDS = [
        "timestamp",
        "host",
        "user",
        "event_id",
        "event_type",
        "source",
        "severity",
        "tenant_id",
        "integrity_hash",
    ]

    # Optional fields
    OPTIONAL_FIELDS = [
        "process_name",
        "command_line",
        "ip_address",
        "raw_event",
    ]

    # Valid severity levels
    VALID_SEVERITIES = {"low", "medium", "high", "critical"}

    # Valid event types
    VALID_EVENT_TYPES = {
        "login_success",
        "login_failure",
        "logout",
        "privilege_escalation",
        "process_creation",
        "process_termination",
        "service_state_change",
        "service_crash",
        "application_crash",
        "application_hang",
        "system_event",
        "file_creation_time",
        "network_connection",
        "driver_loaded",
        "image_loaded",
        "remote_thread_creation",
        "raw_access_read",
        "process_access",
        "file_create",
        "registry_create_delete",
        "registry_value_set",
        "registry_key_value_rename",
        "file_create_stream_hash",
        "pipe_created",
        "pipe_connected",
        "wmi_filter",
        "wmi_consumer",
        "wmi_consumer_filter",
        "dns_query",
        "file_delete",
        "clipboard_change",
        "process_tampering",
        "file_delete_logged",
    }

    # Valid sources
    VALID_SOURCES = {"windows_security", "windows_system", "windows_application", "sysmon"}

    def __init__(self):
        self.logger = logging.getLogger("schema_validator")

    def validate_event(self, event: Dict[str, Any]) -> ValidationResult:
        """
        Validate a single telemetry event.

        Args:
            event: The event dictionary to validate

        Returns:
            ValidationResult with success status and any errors
        """
        errors = []

        # Check required fields
        for field in self.REQUIRED_FIELDS:
            if field not in event:
                errors.append(f"Missing required field: {field}")
            elif event[field] is None:
                errors.append(f"Required field is null: {field}")

        if errors:
            return ValidationResult(False, errors)

        # Validate field types and values
        errors.extend(self._validate_timestamp(event.get("timestamp")))
        errors.extend(self._validate_host(event.get("host")))
        errors.extend(self._validate_user(event.get("user")))
        errors.extend(self._validate_event_id(event.get("event_id")))
        errors.extend(self._validate_event_type(event.get("event_type")))
        errors.extend(self._validate_source(event.get("source")))
        errors.extend(self._validate_severity(event.get("severity")))
        errors.extend(self._validate_tenant_id(event.get("tenant_id")))
        errors.extend(self._validate_integrity_hash(event.get("integrity_hash")))

        # Validate optional fields if present
        if "process_name" in event:
            errors.extend(self._validate_process_name(event["process_name"]))
        if "command_line" in event:
            errors.extend(self._validate_command_line(event["command_line"]))
        if "ip_address" in event:
            errors.extend(self._validate_ip_address(event["ip_address"]))
        if "raw_event" in event:
            errors.extend(self._validate_raw_event(event["raw_event"]))

        return ValidationResult(len(errors) == 0, errors)

    def validate_events(self, events: List[Dict[str, Any]]) -> List[ValidationResult]:
        """
        Validate multiple events.

        Args:
            events: List of event dictionaries

        Returns:
            List of ValidationResult objects
        """
        return [self.validate_event(event) for event in events]

    def _validate_timestamp(self, timestamp: Any) -> List[str]:
        """Validate timestamp field."""
        errors = []
        if not isinstance(timestamp, str):
            errors.append("timestamp must be a string")
            return errors

        try:
            # Try to parse as ISO format
            datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            errors.append("timestamp must be in ISO format")

        return errors

    def _validate_host(self, host: Any) -> List[str]:
        """Validate host field."""
        errors = []
        if not isinstance(host, str):
            errors.append("host must be a string")
        elif not host.strip():
            errors.append("host cannot be empty")
        elif len(host) > 255:
            errors.append("host name too long (max 255 characters)")
        return errors

    def _validate_user(self, user: Any) -> List[str]:
        """Validate user field."""
        errors = []
        if not isinstance(user, str):
            errors.append("user must be a string")
        elif len(user) > 256:
            errors.append("user name too long (max 256 characters)")
        return errors

    def _validate_event_id(self, event_id: Any) -> List[str]:
        """Validate event_id field."""
        errors = []
        if not isinstance(event_id, int):
            errors.append("event_id must be an integer")
        elif event_id < 0 or event_id > 65535:
            errors.append("event_id must be between 0 and 65535")
        return errors

    def _validate_event_type(self, event_type: Any) -> List[str]:
        """Validate event_type field."""
        errors = []
        if not isinstance(event_type, str):
            errors.append("event_type must be a string")
        elif event_type not in self.VALID_EVENT_TYPES:
            errors.append(f"event_type '{event_type}' is not valid")
        return errors

    def _validate_source(self, source: Any) -> List[str]:
        """Validate source field."""
        errors = []
        if not isinstance(source, str):
            errors.append("source must be a string")
        elif source not in self.VALID_SOURCES:
            errors.append(f"source '{source}' is not valid")
        return errors

    def _validate_severity(self, severity: Any) -> List[str]:
        """Validate severity field."""
        errors = []
        if not isinstance(severity, str):
            errors.append("severity must be a string")
        elif severity not in self.VALID_SEVERITIES:
            errors.append(f"severity '{severity}' is not valid")
        return errors

    def _validate_tenant_id(self, tenant_id: Any) -> List[str]:
        """Validate tenant_id field."""
        errors = []
        if not isinstance(tenant_id, str):
            errors.append("tenant_id must be a string")
        elif not tenant_id.strip():
            errors.append("tenant_id cannot be empty")
        elif len(tenant_id) > 128:
            errors.append("tenant_id too long (max 128 characters)")
        return errors

    def _validate_integrity_hash(self, integrity_hash: Any) -> List[str]:
        """Validate integrity_hash field."""
        errors = []
        if not isinstance(integrity_hash, str):
            errors.append("integrity_hash must be a string")
        elif len(integrity_hash) != 64:
            errors.append("integrity_hash must be 64 characters (SHA256)")
        elif not re.match(r'^[a-f0-9]{64}$', integrity_hash):
            errors.append("integrity_hash must be valid hexadecimal")
        return errors

    def _validate_process_name(self, process_name: Any) -> List[str]:
        """Validate process_name field."""
        errors = []
        if not isinstance(process_name, str):
            errors.append("process_name must be a string")
        elif len(process_name) > 1024:
            errors.append("process_name too long (max 1024 characters)")
        return errors

    def _validate_command_line(self, command_line: Any) -> List[str]:
        """Validate command_line field."""
        errors = []
        if not isinstance(command_line, str):
            errors.append("command_line must be a string")
        elif len(command_line) > 4096:
            errors.append("command_line too long (max 4096 characters)")
        return errors

    def _validate_ip_address(self, ip_address: Any) -> List[str]:
        """Validate ip_address field."""
        errors = []
        if not isinstance(ip_address, str):
            errors.append("ip_address must be a string")
        elif ip_address and not self._is_valid_ip(ip_address):
            errors.append("ip_address must be a valid IPv4 or IPv6 address")
        return errors

    def _validate_raw_event(self, raw_event: Any) -> List[str]:
        """Validate raw_event field."""
        errors = []
        if not isinstance(raw_event, dict):
            errors.append("raw_event must be a dictionary")
        elif len(str(raw_event)) > 10000:  # Rough size check
            errors.append("raw_event too large (max ~10KB)")
        return errors

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Check if string is a valid IP address."""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def get_schema_definition(self) -> Dict[str, Any]:
        """Get the JSON schema definition for validation."""
        return {
            "type": "object",
            "required": self.REQUIRED_FIELDS,
            "properties": {
                "timestamp": {
                    "type": "string",
                    "format": "date-time",
                    "description": "ISO 8601 timestamp"
                },
                "host": {
                    "type": "string",
                    "maxLength": 255,
                    "description": "Host machine name"
                },
                "user": {
                    "type": "string",
                    "maxLength": 256,
                    "description": "User associated with event"
                },
                "event_id": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 65535,
                    "description": "Windows Event ID"
                },
                "event_type": {
                    "type": "string",
                    "enum": list(self.VALID_EVENT_TYPES),
                    "description": "Normalized event type"
                },
                "source": {
                    "type": "string",
                    "enum": list(self.VALID_SOURCES),
                    "description": "Event source"
                },
                "process_name": {
                    "type": "string",
                    "maxLength": 1024,
                    "description": "Process name (optional)"
                },
                "command_line": {
                    "type": "string",
                    "maxLength": 4096,
                    "description": "Command line (optional)"
                },
                "ip_address": {
                    "type": "string",
                    "description": "IP address (optional)"
                },
                "severity": {
                    "type": "string",
                    "enum": list(self.VALID_SEVERITIES),
                    "description": "Event severity"
                },
                "tenant_id": {
                    "type": "string",
                    "maxLength": 128,
                    "description": "Tenant identifier"
                },
                "integrity_hash": {
                    "type": "string",
                    "pattern": "^[a-f0-9]{64}$",
                    "description": "SHA256 integrity hash"
                },
                "raw_event": {
                    "type": "object",
                    "description": "Original raw event data"
                }
            }
        }


class ValidationResult:
    """Result of event validation."""

    def __init__(self, is_valid: bool, errors: List[str]):
        self.is_valid = is_valid
        self.errors = errors

    def __bool__(self) -> bool:
        return self.is_valid

    def __str__(self) -> str:
        if self.is_valid:
            return "Valid"
        return f"Invalid: {', '.join(self.errors)}"


# Global validator instance
_validator_instance: Optional[WindowsTelemetrySchemaValidator] = None


def get_schema_validator() -> WindowsTelemetrySchemaValidator:
    """Get or create global schema validator instance."""
    global _validator_instance
    if _validator_instance is None:
        _validator_instance = WindowsTelemetrySchemaValidator()
    return _validator_instance


def validate_windows_event(event: Dict[str, Any]) -> ValidationResult:
    """Validate a single Windows telemetry event."""
    validator = get_schema_validator()
    return validator.validate_event(event)


def validate_windows_events(events: List[Dict[str, Any]]) -> List[ValidationResult]:
    """Validate multiple Windows telemetry events."""
    validator = get_schema_validator()
    return validator.validate_events(events)