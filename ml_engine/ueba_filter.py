"""
UEBA Event Filtering Layer

CRITICAL COMPONENT: Filters events to only allow identity-aware authentication
events into the UEBA baseline engine.

This layer is essential because:
- UEBA must NOT consume raw system logs
- UEBA must ONLY process normalized identity events
- Raw telemetry (processes, network, files) corrupts baselines
- Only authentication events (login, logout, failure) are relevant

Filtering Rules:
ALLOWED (these events build identity baselines):
- login_success
- login_failure
- logout_event

REJECTED (these do NOT contribute to UEBA):
- process_creation
- process_termination
- network_connection
- file_write
- dll_load
- etc.

This ensures UEBA produces meaningful behavioral baselines focused on
user identity patterns, not system activity.
"""

from __future__ import annotations

from typing import Any

from core.safe_wrapper import log_health_event


# Define allowed UEBA event types
# ONLY these events are permitted into the baseline engine
ALLOWED_UEBA_EVENTS = {
    "login_success",
    "login_failure",
    "logout_event",
}

# Events that must be rejected
REJECTED_EVENT_TYPES = {
    "process_creation",
    "process_termination",
    "process_injection",
    "dll_load",
    "file_write",
    "file_delete",
    "file_access",
    "network_connection",
    "network_listen",
    "registry_set",
    "registry_delete",
    "http_request",
    "dns_query",
    "privilege_escalation",
    "driver_load",
    "system_event",
    "sysmon_event",
    "windows_event",
    "auth",  # Raw event category (use specific auth_event_type)
}


class UebaEventFilter:
    """
    Filtering layer for UEBA event ingestion.
    
    This filter enforces the critical design principle that UEBA must only
    consume identity-aware, normalized authentication events. It rejects
    raw system telemetry that would corrupt user behavior baselines.
    
    Usage:
        filtered_event = UebaEventFilter.filter(event)
        if filtered_event:
            # Add to UEBA baseline engine
            baseline_engine.process(filtered_event)
    """

    @staticmethod
    def is_ueba_event(event: dict[str, Any]) -> bool:
        """
        Check if event is allowed for UEBA processing.
        
        Args:
            event: Event to check
            
        Returns:
            True if event is identity-related auth event, False otherwise
        """
        if not isinstance(event, dict):
            return False

        event_type = str(event.get("event_type", "")).lower()
        source = str(event.get("source", "")).lower()

        # Must be from windows_auth source
        if source != "windows_auth":
            return False

        # Must be in allowed event types
        if event_type not in ALLOWED_UEBA_EVENTS:
            return False

        # Must have required identity fields
        user = event.get("user")
        if not user or str(user).lower() in ("unknown", "system", "local service"):
            return False

        return True

    @staticmethod
    def filter(event: dict[str, Any]) -> dict[str, Any] | None:
        """
        Filter event for UEBA processing.
        
        Args:
            event: Raw event to filter
            
        Returns:
            Event if allowed, None if rejected
        """
        try:
            if not UebaEventFilter.is_ueba_event(event):
                return None

            # Event passes filtering, return as-is
            return event

        except Exception as exc:
            log_health_event(
                "debug",
                "ueba_filter",
                f"Error filtering event: {str(exc)}",
            )
            return None

    @staticmethod
    def batch_filter(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Filter multiple events.
        
        Args:
            events: List of events to filter
            
        Returns:
            List of filtered events (rejects non-UEBA events)
        """
        filtered = []
        for event in events:
            result = UebaEventFilter.filter(event)
            if result is not None:
                filtered.append(result)

        return filtered

    @staticmethod
    def get_filter_stats(
        events: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Analyze filtering statistics for event batch.
        
        Args:
            events: Events to analyze
            
        Returns:
            Stats about filtering results
        """
        total = len(events)
        passed = 0
        rejected_by_type: dict[str, int] = {}
        rejected_by_source: dict[str, int] = {}

        for event in events:
            if UebaEventFilter.is_ueba_event(event):
                passed += 1
            else:
                event_type = str(event.get("event_type", "unknown"))
                source = str(event.get("source", "unknown"))

                rejected_by_type[event_type] = rejected_by_type.get(event_type, 0) + 1
                rejected_by_source[source] = rejected_by_source.get(source, 0) + 1

        return {
            "total_events": total,
            "passed_filter": passed,
            "rejected": total - passed,
            "pass_rate": round(passed / total * 100, 2) if total > 0 else 0,
            "rejected_by_type": rejected_by_type,
            "rejected_by_source": rejected_by_source,
        }
