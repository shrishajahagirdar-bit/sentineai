from __future__ import annotations

from typing import Any


class AlertGenerator:
    def generate(self, event: dict[str, Any], scoring_result: dict[str, Any]) -> dict[str, Any]:
        return {
            "event_id": scoring_result["event_id"],
            "risk_score": scoring_result["risk_score"],
            "severity": scoring_result["severity"],
            "alert": bool(scoring_result["alert"]),
            "reason": list(scoring_result["reason"]),
            "event_type": str(event.get("event_type", "unknown")),
            "source": str(event.get("source", "unknown")),
            "user": str(event.get("user", "unknown")),
            "attack_type": str(event.get("attack_type", "none")),
        }
