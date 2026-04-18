from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta
from typing import Any


ATTACK_TYPE_WEIGHTS = {
    "brute_force": 2.0,
    "ddos": 3.0,
    "insider_threat": 4.0,
    "insider": 4.0,
}

SEVERITY_SCORES = {
    "low": 0.25,
    "medium": 0.5,
    "high": 0.8,
    "critical": 1.0,
}


def clamp_score(score: float) -> int:
    return int(max(0.0, min(score, 100.0)))


def severity_to_score(severity: str) -> float:
    return float(SEVERITY_SCORES.get(str(severity).lower(), 0.25))


def behavioral_reasons(event: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    parsed_fields = event.get("parsed_fields", {})
    if not isinstance(parsed_fields, dict):
        parsed_fields = {}

    if float(parsed_fields.get("login_failure_count", 0.0) or 0.0) >= 5:
        reasons.append("login_anomaly")
    if float(event.get("ip_change_frequency", parsed_fields.get("ip_change_frequency", 0.0)) or 0.0) >= 0.5:
        reasons.append("ip_change_detected")
    if bool(parsed_fields.get("access_time_anomaly")):
        reasons.append("access_time_violation")
    return reasons


class RuleEngine:
    def __init__(self) -> None:
        self.failed_logins: dict[str, deque[datetime]] = {}

    def evaluate(self, event: dict[str, Any]) -> tuple[float, list[str]]:
        score = 0.0
        reasons = behavioral_reasons(event)
        user = str(event.get("user", "unknown"))

        timestamp = str(event.get("timestamp", ""))
        try:
            now = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            now = datetime.utcnow()

        if event.get("event_type") == "login_failure":
            failures = self.failed_logins.setdefault(user, deque())
            failures.append(now)
            while failures and now - failures[0] > timedelta(minutes=15):
                failures.popleft()
            if len(failures) >= 5:
                score += 0.2
                reasons.append("failed login burst")

        attack_weight = ATTACK_TYPE_WEIGHTS.get(str(event.get("attack_type", "none")).lower(), 0.0)
        score += min(attack_weight * 0.1, 0.4)
        return min(score, 1.0), sorted(set(reasons))
