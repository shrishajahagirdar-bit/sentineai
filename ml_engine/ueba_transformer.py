"""
UEBA Transformation Layer

Transforms raw Windows authentication events into normalized UEBA events.
This layer is critical for converting identity-aware events into the format
expected by the baseline engine and dashboard.

Transformation Rules:
- 4624 (Successful login) → login_success
- 4625 (Failed login) → login_failure
- 4634/4647 (Logout) → logout_event

UEBA Event Format:
{
    "user": str,
    "device": str,
    "event_type": "login_success" | "login_failure" | "logout_event",
    "timestamp": str (ISO 8601),
    "source": "windows_auth",
    "ip_address": str,
    "logon_type": str,
    "risk_signals": {
        "failed_login": bool,
        "new_device": bool,
        "impossible_travel": bool,
        "brute_force_attempt": bool
    },
    "raw_source": "windows_security",
    "record_id": int
}
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from core.safe_wrapper import log_health_event


class UebaEventTransformer:
    """
    Transforms raw authentication events into UEBA-compatible events.
    
    This transformer is the bridge between raw Windows Security Log events
    and the UEBA baseline engine. It:
    
    1. Validates event structure
    2. Maps event IDs to UEBA event types
    3. Extracts risk signals (failed login, new device, etc.)
    4. Normalizes timestamp and device info
    """

    @staticmethod
    def to_ueba_event(event: dict[str, Any]) -> dict[str, Any] | None:
        """
        Transform raw authentication event to UEBA format.
        
        Args:
            event: Raw event from Windows Auth Collector
            
        Returns:
            Normalized UEBA event or None if transformation fails
        """
        try:
            # Validate required fields
            if not isinstance(event, dict):
                return None

            event_id = event.get("event_id")
            user = event.get("user")
            
            if not event_id or not user or user == "unknown":
                return None

            # Determine UEBA event type from Windows Event ID
            ueba_event_type = UebaEventTransformer._map_event_type(event_id)
            if not ueba_event_type:
                return None

            # Extract fields
            hostname = event.get("host") or event.get("source_device")
            timestamp = event.get("timestamp") or datetime.utcnow().isoformat()
            ip_address = event.get("ip_address", "unknown")
            logon_type = event.get("logon_type", "unknown")
            record_id = event.get("record_number", 0)

            # Calculate risk signals
            risk_signals = UebaEventTransformer._calculate_risk_signals(
                event_id, logon_type
            )

            # Build UEBA event
            ueba_event = {
                # Identity fields
                "user": str(user).strip(),
                "device": str(hostname).strip() if hostname else "unknown",
                "source_device": str(hostname).strip() if hostname else "unknown",
                
                # Event classification
                "event_type": ueba_event_type,
                "auth_event_id": event_id,
                
                # Temporal
                "timestamp": str(timestamp),
                
                # Source tracking
                "source": "windows_auth",
                "raw_source": "windows_security",
                "collection_source": "windows_auth_collector",
                
                # Network
                "ip_address": str(ip_address),
                "logon_type": str(logon_type),
                
                # Risk signals for anomaly detection
                "risk_signals": risk_signals,
                
                # Tracking
                "record_id": int(record_id),
                "status": "ok",
                
                # Metadata
                "metadata": {
                    "collector": "windows_auth",
                    "event_id": event_id,
                    "transformation": "ueba_transformer_v1",
                },
            }

            return ueba_event

        except Exception as exc:
            log_health_event(
                "debug",
                "ueba_transformer",
                f"Failed to transform event: {str(exc)}",
            )
            return None

    @staticmethod
    def _map_event_type(event_id: int) -> str | None:
        """Map Windows Event ID to UEBA event type."""
        event_mapping = {
            4624: "login_success",
            4625: "login_failure",
            4634: "logout_event",
            4647: "logout_event",
        }
        return event_mapping.get(event_id)

    @staticmethod
    def _calculate_risk_signals(event_id: int, logon_type: str) -> dict[str, bool]:
        """
        Calculate initial risk signals based on event characteristics.
        
        These signals are used by the baseline engine for anomaly detection:
        - failed_login: indicates authentication failure
        - new_device: placeholder for device fingerprinting (set by baseline)
        - impossible_travel: placeholder for geographic anomaly (set by baseline)
        - brute_force_attempt: indicator of multiple failed attempts
        """
        return {
            "failed_login": event_id == 4625,
            "new_device": False,  # Set by baseline engine after comparison
            "impossible_travel": False,  # Set by baseline engine
            "brute_force_attempt": False,  # Requires aggregation by baseline
            "unusual_logon_type": logon_type
            in ("RemoteInteractive", "NetworkCleartext", "NewCredentials"),
        }

    @staticmethod
    def batch_transform(
        events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Transform multiple events in batch.
        
        Args:
            events: List of raw events
            
        Returns:
            List of transformed UEBA events (filters out failed transforms)
        """
        transformed = []
        for event in events:
            ueba_event = UebaEventTransformer.to_ueba_event(event)
            if ueba_event is not None:
                transformed.append(ueba_event)

        return transformed
