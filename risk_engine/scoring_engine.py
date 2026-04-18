from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from risk_engine.rules import ATTACK_TYPE_WEIGHTS, behavioral_reasons, clamp_score, severity_to_score


@dataclass
class ScoringResult:
    event_id: str
    risk_score: int
    severity: str
    alert: bool
    reason: list[str]
    components: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "alert": self.alert,
            "reason": self.reason,
            "components": self.components,
        }


class ScoringEngine:
    def score(self, event: dict[str, Any]) -> ScoringResult:
        ml_score = float(event.get("ml_score", 0.0) or 0.0)
        ueba_score = float(event.get("user_behavior_score", 0.0) or 0.0)
        severity_score = severity_to_score(str(event.get("severity", "low")))
        attack_weight = ATTACK_TYPE_WEIGHTS.get(str(event.get("attack_type", "none")).lower(), 0.0)
        frequency = float(event.get("frequency", event.get("request_rate", 0.0)) or 0.0)

        reasons = behavioral_reasons(event)
        if ml_score >= 0.7:
            reasons.append("ml_anomaly")
        if ueba_score >= 0.5:
            reasons.append("ueba_deviation")
        if attack_weight > 0:
            reasons.append(f"{str(event.get('attack_type', 'unknown')).lower()}_detected")
        if frequency >= 0.7:
            reasons.append("frequency_spike")

        raw_score = (ml_score * 40.0) + (ueba_score * 30.0) + (severity_score * 20.0) + (attack_weight * 10.0)
        risk_score = clamp_score(raw_score)
        severity = self._severity(risk_score)
        return ScoringResult(
            event_id=str(event.get("event_id", "unknown")),
            risk_score=risk_score,
            severity=severity,
            alert=risk_score >= 30,
            reason=sorted(set(reasons)),
            components={
                "ml_score": round(ml_score, 4),
                "ueba_score": round(ueba_score, 4),
                "severity_score": round(severity_score, 4),
                "attack_type_weight": round(attack_weight, 4),
            },
        )

    @staticmethod
    def _severity(risk_score: int) -> str:
        if risk_score >= 80:
            return "critical"
        if risk_score >= 60:
            return "high"
        if risk_score >= 30:
            return "medium"
        return "low"
