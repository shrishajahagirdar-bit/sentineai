from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

import numpy as np
import pandas as pd

from backend.models.schemas import AnalyzeRequest
from backend.services.attack_story import build_incident_story
from backend.services.model_registry import ModelRegistry
from backend.services.ueba import UebaService


@dataclass
class RiskResult:
    event_id: str | None
    risk_score: float
    severity: str
    response_action: str
    supervised_probability: float
    anomaly_score: float
    behavior_deviation_score: float
    triggered_rules: list[str]
    explanation: str
    incident_story: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class RiskEngine:
    def __init__(self, registry: ModelRegistry, ueba_service: UebaService) -> None:
        self.registry = registry
        self.ueba_service = ueba_service

    def score_event(self, request: AnalyzeRequest) -> RiskResult:
        frame = self._build_model_frame(request)
        supervised_probability = self._score_supervised(frame)
        anomaly_score = self._score_anomaly(frame)
        behavior_score, behavior_reasons = self.ueba_service.score_behavior(request)

        base_score = (0.6 * supervised_probability) + (0.4 * anomaly_score) + behavior_score
        risk_score = float(np.clip(base_score * 100, 0, 100))

        rules = self._apply_rules(request)
        triggered_rules = rules["triggered_rules"] + behavior_reasons
        risk_score = float(np.clip(risk_score + rules["adjustment"], 0, 100))

        severity = self._severity(risk_score)
        response_action = self._response_action(risk_score)
        explanation = self._build_explanation(
            supervised_probability,
            anomaly_score,
            behavior_score,
            rules["adjustment"],
            triggered_rules,
        )
        story = build_incident_story(
            user_id=request.user_id,
            action=request.action,
            triggered_rules=triggered_rules,
            response_action=response_action,
            severity=severity,
        )

        return RiskResult(
            event_id=request.event_id,
            risk_score=round(risk_score, 2),
            severity=severity,
            response_action=response_action,
            supervised_probability=round(supervised_probability, 4),
            anomaly_score=round(anomaly_score, 4),
            behavior_deviation_score=round(behavior_score, 4),
            triggered_rules=triggered_rules,
            explanation=explanation,
            incident_story=story,
        )

    def _build_model_frame(self, request: AnalyzeRequest) -> pd.DataFrame:
        data = {
            "dataset": request.dataset or "live",
            "src_ip": request.source_ip or request.raw_features.get("src_ip", "unknown"),
            "dst_ip": request.destination_ip or request.raw_features.get("dst_ip", "unknown"),
            "src_port": request.raw_features.get("src_port", 0),
            "dst_port": request.raw_features.get("dst_port", 0),
            "protocol": request.raw_features.get("protocol", "unknown"),
            "service": request.raw_features.get("service", "unknown"),
            "state": request.raw_features.get("state", "unknown"),
            "duration": request.raw_features.get("duration", 0.0),
            "bytes_sent": request.bytes_sent if request.bytes_sent is not None else request.raw_features.get("bytes_sent", 0.0),
            "bytes_received": request.bytes_received if request.bytes_received is not None else request.raw_features.get("bytes_received", 0.0),
            "packets": request.raw_features.get("packets", 0.0),
            "user_id": request.user_id or "unknown",
            "action": request.action or request.raw_features.get("action", "unknown"),
            "hour": (request.timestamp or datetime.utcnow()).hour,
        }
        data.update(request.raw_features)
        return pd.DataFrame([data])

    def _score_supervised(self, frame: pd.DataFrame) -> float:
        if self.registry.supervised is None:
            return 0.0

        try:
            probabilities = self.registry.supervised.predict_proba(frame)
            return float(probabilities[0][1])
        except Exception:
            return 0.0

    def _score_anomaly(self, frame: pd.DataFrame) -> float:
        if self.registry.unsupervised is None:
            return 0.0

        try:
            raw_score = float(self.registry.unsupervised.decision_function(frame)[0])
            return float(np.clip((0.5 - raw_score), 0.0, 1.0))
        except Exception:
            return 0.0

    def _apply_rules(self, request: AnalyzeRequest) -> dict[str, Any]:
        adjustment = 0
        triggered_rules: list[str] = []

        if request.failed_logins > 3:
            adjustment += 20
            triggered_rules.append("failed_logins>3")
        if request.unusual_location:
            adjustment += 25
            triggered_rules.append("unusual_location")
        if request.unusual_time:
            adjustment += 15
            triggered_rules.append("unusual_time")
        if request.sensitive_file_access:
            adjustment += 30
            triggered_rules.append("sensitive_file_access")
        if request.bulk_download:
            adjustment += 25
            triggered_rules.append("bulk_download")
        if request.privilege_escalation:
            adjustment += 40
            triggered_rules.append("privilege_escalation")

        return {"adjustment": adjustment, "triggered_rules": triggered_rules}

    @staticmethod
    def _severity(score: float) -> str:
        if score >= 85:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 30:
            return "medium"
        return "low"

    @staticmethod
    def _response_action(score: float) -> str:
        if score >= 85:
            return "Block sensitive actions and downloads"
        if score >= 60:
            return "Restrict sensitive actions"
        if score >= 30:
            return "Alert SOC analyst"
        return "Monitor"

    @staticmethod
    def _build_explanation(
        supervised_probability: float,
        anomaly_score: float,
        behavior_score: float,
        rule_adjustment: int,
        triggered_rules: list[str],
    ) -> str:
        rule_text = ", ".join(triggered_rules) if triggered_rules else "no explicit SOC rules triggered"
        return (
            f"Supervised model confidence={supervised_probability:.2f}, "
            f"anomaly score={anomaly_score:.2f}, "
            f"behavior deviation={behavior_score:.2f}, "
            f"rule adjustment={rule_adjustment}. Triggered indicators: {rule_text}."
        )

