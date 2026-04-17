from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import pandas as pd

from backend.config import settings
from backend.models.schemas import AnalyzeRequest
from backend.services.data_access import load_profiles


@dataclass
class UserProfile:
    """User behavioral baseline profile."""
    login_time_distribution: dict[str, float]
    location_history: list[str]
    device_fingerprint: list[str]
    activity_sequence_model: list[str]
    total_logins: int = 0
    failed_logins: int = 0


class UebaService:
    """User and Entity Behavior Analytics Engine."""
    
    def __init__(self) -> None:
        self._profiles = load_profiles()
    
    def reload(self) -> None:
        """Reload profiles from disk."""
        self._profiles = load_profiles()
    
    def get_profile(self, user_id: str) -> UserProfile | None:
        """retrieve baseline profile for user."""
        payload = self._profiles.get(user_id)
        if not payload:
            return None
        return UserProfile(
            login_time_distribution=payload.get("login_time_distribution", {}),
            location_history=payload.get("location_history", []),
            device_fingerprint=payload.get("device_fingerprint", []),
            activity_sequence_model=payload.get("activity_sequence_model", []),
            total_logins=payload.get("total_logins", 0),
            failed_logins=payload.get("failed_logins", 0),
        )
    
    def score_behavior(self, request: AnalyzeRequest) -> tuple[float, list[str]]:
        """
        Score event against user baseline behavior.
        
        Returns:
            (score 0-1, list of deviation reasons)
        """
        if not request.user_id:
            return 0.0, []
        
        profile = self.get_profile(request.user_id)
        if profile is None:
            return 0.05, ["new_user_behavior"]
        
        score = 0.0
        reasons: list[str] = []
        
        # ===== Time-based anomaly =====
        if request.timestamp:
            try:
                hour = request.timestamp.hour
                hour_str = str(hour)
                hour_prob = profile.login_time_distribution.get(hour_str, 0.0)
                
                if hour_prob < 0.05:
                    score += 0.15
                    reasons.append("behavior_unusual_time")
                elif hour_prob < 0.10:
                    score += 0.08
                    reasons.append("behavior_atypical_time")
            except:
                pass
        
        # ===== Location anomaly =====
        location_key = None
        if request.source_host and request.destination_host:
            location_key = f"{request.source_host}->{request.destination_host}"
        elif request.source_ip and request.destination_ip:
            location_key = f"{request.source_ip}->{request.destination_ip}"
        
        if location_key and location_key not in profile.location_history:
            score += 0.25
            reasons.append("behavior_unusual_location")
        
        # ===== Device anomaly =====
        device = request.device_id or request.source_host or request.source_ip
        if device and device not in profile.device_fingerprint:
            score += 0.20
            reasons.append("behavior_new_device")
        
        # ===== Action anomaly =====
        action = request.action or request.raw_features.get("action")
        if action and action not in profile.activity_sequence_model:
            score += 0.15
            reasons.append("behavior_rare_action")
        
        # ===== Data access anomaly =====
        if request.bulk_download:
            score += 0.20
            reasons.append("behavior_bulk_data_transfer")
        
        if request.sensitive_file_access:
            score += 0.15
            reasons.append("behavior_sensitive_file_access")
        
        # ===== Failed login spikes =====
        if request.failed_logins > 1:
            score += 0.20
            reasons.append("behavior_multiple_failures")
        
        # ===== Privilege escalation =====
        if request.privilege_escalation:
            score += 0.20
            reasons.append("behavior_privilege_escalation")
        
        return min(score, 1.0), reasons
    
    def rebuild_from_events(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        """Rebuild baselines from authentication event log."""
        self._profiles.clear()
        
        if not events:
            return {}
        
        # Group by user
        df = pd.DataFrame(events)
        df = df[df["user_id"].notna()]
        
        for user_id, user_group in df.groupby("user_id"):
            profile = self._build_user_profile(user_group)
            self._profiles[str(user_id)] = profile
        
        self._save_profiles()
        return self._profiles
    
    def _build_user_profile(self, user_events: pd.DataFrame) -> dict[str, Any]:
        """Build behavioral baseline for single user."""
        # Login time distribution
        login_dist = {}
        if "timestamp" in user_events.columns:
            hours = pd.to_datetime(user_events["timestamp"], errors="coerce").dt.hour
            hour_counts = hours.value_counts(normalize=True)
            login_dist = {str(int(h)): round(float(v), 4) for h, v in hour_counts.items()}
        
        # Location patterns
        locations = []
        if "source_host" in user_events.columns and "destination_host" in user_events.columns:
            loc_pairs = (user_events["source_host"] + "->" + user_events["destination_host"]).unique()
            locations = loc_pairs[:10].tolist()
        
        # Device patterns  
        devices = []
        if "source_host" in user_events.columns:
            devices = user_events["source_host"].unique()[:10].tolist()
        
        # Action patterns
        actions = []
        if "action" in user_events.columns:
            actions = user_events["action"].unique()[:15].tolist()
        
        return {
            "login_time_distribution": login_dist,
            "location_history": locations,
            "device_fingerprint": devices,
            "activity_sequence_model": actions,
            "total_logins": len(user_events),
            "failed_logins": int(user_events.get("failed_logins", 0).sum()),
            "updated_at": datetime.utcnow().isoformat(),
        }
    
    def _save_profiles(self) -> None:
        """Persist profiles to disk."""
        settings.profile_file.parent.mkdir(parents=True, exist_ok=True)
        with open(settings.profile_file, "w", encoding="utf-8") as f:
            json.dump(self._profiles, f, indent=2)


def summarize_risk_factors(profile_payload: dict[str, Any]) -> list[str]:
    """Extract risk factors from user profile."""
    risk_factors: list[str] = []
    
    total_logins = profile_payload.get("total_logins", 0)
    
    if total_logins < 5:
        risk_factors.append("Low activity user (limited baseline)")
    
    if len(profile_payload.get("device_fingerprint", [])) > 10:
        risk_factors.append("High device diversity")
    
    if len(profile_payload.get("location_history", [])) > 5:
        risk_factors.append("Multi-location user")
    
    if profile_payload.get("failed_logins", 0) > 3:
        risk_factors.append("High auth failure rate")
    
    return risk_factors

