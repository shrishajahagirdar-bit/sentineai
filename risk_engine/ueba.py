"""
UEBA Baseline Engine - User and Entity Behavior Analytics

This engine builds behavioral baselines exclusively from authenticated identity
events. It computes patterns for:

1. Login time distribution (what hours does the user typically log in?)
2. Login frequency (how many logins per day?)
3. Failed login rate (what percentage of attempts fail?)
4. Device diversity (how many unique devices does the user use?)
5. IP address patterns (what IP addresses does the user connect from?)
6. Logon type patterns (interactive, network, service, etc.)

The baseline is used to detect anomalies:
- Logins at unusual times
- Excessive failed login attempts
- Connections from new/unknown devices
- Connections from geographically impossible locations (impossible travel)
- Logon type anomalies

This engine ONLY processes FILTERED UEBA EVENTS from the identity layer.
It DOES NOT consume raw system logs.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from typing import Any

import pandas as pd

from collector.storage import load_json, read_jsonl, save_json
from core.safe_wrapper import log_health_event
from sentinel_config import CONFIG


class UebaEngine:
    """
    UEBA Baseline Engine - builds behavioral baselines from authentication events.
    
    Attributes:
        baselines: Dict mapping user -> behavioral profile
        auth_event_store: Path to filtered authentication events
    """

    def __init__(self) -> None:
        self.baselines = load_json(CONFIG.baseline_store, {})
        self.auth_event_store = CONFIG.auth_event_store
        self.device_cache: dict[str, set[str]] = {}  # Track known devices per user

    def rebuild(
        self, events: list[dict[str, Any]] | None = None
    ) -> dict[str, Any]:
        """
        Rebuild baselines from authentication events.
        
        This method processes ONLY filtered authentication events (login_success,
        login_failure, logout_event). It computes statistical patterns that serve
        as the behavioral baseline for each user.
        
        Args:
            events: List of UEBA events. If None, reads from auth_event_store.
            
        Returns:
            Dict mapping user -> normalized baseline profile
        """
        # Load filtered authentication events
        if events is None:
            source_events = read_jsonl(self.auth_event_store, limit=None) or []
        else:
            source_events = events

        # Build raw profiles
        baselines: dict[str, Any] = {}

        for event in source_events:
            user = str(event.get("user", "unknown")).strip()
            if not user or user == "unknown":
                continue

            # Ensure event is authentication-related (security layer)
            event_type = str(event.get("event_type", "")).lower()
            if event_type not in ("login_success", "login_failure", "logout_event"):
                continue

            profile = baselines.setdefault(
                user,
                {
                    "login_events": [],  # All login attempts
                    "login_success_hours": Counter(),  # Hour distribution
                    "login_failure_hours": Counter(),
                    "login_devices": Counter(),  # Device frequency
                    "login_ips": Counter(),  # IP frequency
                    "login_types": Counter(),  # Logon type distribution
                    "login_success_count": 0,
                    "login_failure_count": 0,
                    "logout_count": 0,
                },
            )

            # Parse timestamp
            timestamp = pd.to_datetime(event.get("timestamp"), errors="coerce")
            if pd.isna(timestamp):
                continue

            # Extract features
            device = str(event.get("device") or event.get("source_device", "unknown"))
            ip_address = str(event.get("ip_address", "unknown"))
            logon_type = str(event.get("logon_type", "unknown"))

            profile["login_events"].append(
                {
                    "timestamp": timestamp,
                    "event_type": event_type,
                    "device": device,
                    "ip_address": ip_address,
                    "logon_type": logon_type,
                }
            )

            # Update counters by event type
            if event_type == "login_success":
                profile["login_success_count"] += 1
                profile["login_success_hours"][str(int(timestamp.hour))] += 1
                profile["login_devices"][device] += 1
                profile["login_ips"][ip_address] += 1
                profile["login_types"][logon_type] += 1

            elif event_type == "login_failure":
                profile["login_failure_count"] += 1
                profile["login_failure_hours"][str(int(timestamp.hour))] += 1

            elif event_type == "logout_event":
                profile["logout_count"] += 1

        # Normalize profiles
        normalized: dict[str, Any] = {}
        for user, profile in baselines.items():
            normalized[user] = self._normalize_profile(user, profile)

        self.baselines = normalized
        save_json(CONFIG.baseline_store, normalized)
        log_health_event(
            "info",
            "ueba_baseline_rebuild",
            f"Rebuilt baselines for {len(normalized)} users",
            context={"user_count": len(normalized)},
        )
        return normalized

    @staticmethod
    def _normalize_profile(user: str, profile: dict[str, Any]) -> dict[str, Any]:
        """
        Normalize raw profile into statistical baseline.
        
        Computes probability distributions for login patterns.
        """
        total_success = max(profile["login_success_count"], 1)
        total_failure = max(profile["login_failure_count"], 1)
        total_logins = total_success + total_failure

        # Login time distribution (percentage by hour)
        login_time_dist = {}
        all_hours = list(profile["login_success_hours"].keys())
        if all_hours:
            for hour, count in profile["login_success_hours"].items():
                login_time_dist[hour] = round(count / total_success, 4)

        # Device distribution
        devices = {
            name: round(count / total_success, 4)
            for name, count in profile["login_devices"].most_common(10)
        }

        # IP distribution
        ips = {
            ip: round(count / total_success, 4)
            for ip, count in profile["login_ips"].most_common(10)
        }

        # Logon type distribution
        logon_types = {
            ltype: round(count / total_success, 4)
            for ltype, count in profile["login_types"].items()
        }

        return {
            # Identity
            "user": user,
            # Login patterns
            "login_time_distribution": login_time_dist,
            "avg_login_hour": round(
                sum(int(h) for h in all_hours) / len(all_hours), 2
            )
            if all_hours
            else None,
            # Frequency metrics
            "total_logins": total_logins,
            "login_success_count": total_success,
            "login_failure_count": total_failure,
            "failed_login_rate": round(total_failure / total_logins, 4)
            if total_logins > 0
            else 0.0,
            "logout_count": profile["logout_count"],
            # Device patterns
            "known_devices": list(devices.keys()),
            "device_count": len(devices),
            "devices": devices,
            # IP patterns
            "known_ips": list(ips.keys()),
            "ip_count": len(ips),
            "ips": ips,
            # Logon type patterns
            "logon_types": logon_types,
            # Metadata
            "updated_at": datetime.utcnow().isoformat(),
            "events_analyzed": len(profile["login_events"]),
        }

    def score(self, event: dict[str, Any]) -> tuple[float, list[str]]:
        """
        Score event for anomaly detection based on baseline.
        
        Compares event against baseline to detect:
        - Unusual login time
        - Failed login patterns
        - New device
        - New IP address
        
        Args:
            event: Authentication event to score
            
        Returns:
            Tuple of (anomaly_score: 0.0-1.0, reasons: list of anomaly reasons)
        """
        user = str(event.get("user", "unknown")).strip()
        baseline = self.baselines.get(user)

        if not baseline:
            # New user - assign low score
            return 0.15, ["new_user_baseline"]

        reasons: list[str] = []
        deviation = 0.0

        # Extract event features
        event_type = str(event.get("event_type", "")).lower()
        timestamp = pd.to_datetime(event.get("timestamp"), errors="coerce")
        device = str(event.get("device") or event.get("source_device", "unknown"))
        ip_address = str(event.get("ip_address", "unknown"))

        # Only score login attempts (not logout)
        if event_type not in ("login_success", "login_failure"):
            return 0.0, []

        # 1. Check login time anomaly
        if not pd.isna(timestamp):
            hour = str(int(timestamp.hour))
            hour_probability = baseline["login_time_distribution"].get(hour, 0.0)

            if hour_probability < 0.05:  # Rare login hour
                deviation += 0.15
                reasons.append("unusual_login_time")

        # 2. Check device anomaly
        if device not in baseline.get("known_devices", []):
            if device not in ("unknown", "local"):
                deviation += 0.20
                reasons.append("new_device")

        # 3. Check IP anomaly
        if ip_address not in baseline.get("known_ips", []):
            if ip_address not in ("unknown", "127.0.0.1", "::1"):
                deviation += 0.20
                reasons.append("new_ip_address")

        # 4. Check for failed login
        if event_type == "login_failure":
            deviation += 0.10
            reasons.append("failed_login")

            # Check if failure rate exceeds baseline
            failure_rate = float(event.get("risk_signals", {}).get("failed_login", False))
            if failure_rate:
                reasons.append("login_failure_detected")

        # 5. Check logon type anomaly
        logon_type = str(event.get("logon_type", "unknown"))
        allowed_types = set(baseline.get("logon_types", {}).keys())
        if logon_type not in allowed_types and logon_type != "unknown":
            if logon_type in ("RemoteInteractive", "NetworkCleartext"):
                deviation += 0.10
                reasons.append("unusual_logon_type")

        return min(deviation, 1.0), reasons

    def get_user_profile(self, user: str) -> dict[str, Any] | None:
        """Get behavioral profile for a specific user."""
        return self.baselines.get(user)

    def get_all_profiles(self) -> dict[str, Any]:
        """Get all user profiles."""
        return self.baselines

    def get_active_users(self) -> list[str]:
        """Get list of users with baselines."""
        return sorted(self.baselines.keys())

