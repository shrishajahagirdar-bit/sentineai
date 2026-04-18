from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from collector.storage import append_jsonl, read_jsonl
from core.safe_wrapper import safe_execution
from core.transformers import normalize_event
from ml_engine.inference import LiveModelEngine
from risk_engine.alert_generator import AlertGenerator
from risk_engine.incident_builder import IncidentBuilder
from risk_engine.rules import RuleEngine
from risk_engine.scoring_engine import ScoringEngine
from risk_engine.story import build_attack_story
from risk_engine.ueba import UebaEngine
from sentinel_config import CONFIG


@dataclass
class RiskAssessment:
    timestamp: str
    user: str
    source: str
    event_type: str
    risk_score: float
    severity: str
    response_action: str
    ml_prediction: float
    anomaly_score: float
    rule_engine_score: float
    behavior_score: float
    triggers: list[str]
    story: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class RiskPipeline:
    def __init__(self) -> None:
        self.models = LiveModelEngine()
        self.rules = RuleEngine()
        self.ueba = UebaEngine()
        self.incidents = IncidentBuilder()
        self.scoring = ScoringEngine()
        self.alerts = AlertGenerator()

    def refresh_models(self) -> None:
        self.models.reload()
        self.ueba = UebaEngine()

    @safe_execution(
        default_factory=lambda: RiskAssessment(
            timestamp=datetime.utcnow().isoformat(),
            user="unknown",
            source="middleware",
            event_type="fallback",
            risk_score=0.0,
            severity="low",
            response_action="Monitor",
            ml_prediction=0.0,
            anomaly_score=0.0,
            rule_engine_score=0.0,
            behavior_score=0.0,
            triggers=[],
            story="data unavailable",
            message="data unavailable",
        ),
        operation="risk_assess",
    )
    def assess(self, event: dict[str, Any], persist: bool = True) -> RiskAssessment:
        normalized_event = normalize_event(event)
        ml_output = self.models.predict_output(normalized_event)
        ml_prediction = float(ml_output.get("risk_score", 0.0))
        anomaly_score = float(ml_output.get("anomaly_score", 0.0))
        rule_score, rule_triggers = self.rules.evaluate(normalized_event)
        behavior_score, behavior_reasons = self.ueba.score(normalized_event)

        scoring_input = {
            **normalized_event,
            "ml_score": ml_prediction,
            "user_behavior_score": behavior_score,
            "frequency": min(rule_score + anomaly_score, 1.0),
        }
        scoring_result = self.scoring.score(scoring_input).to_dict()

        risk_score = float(scoring_result["risk_score"])
        triggers = sorted(set(rule_triggers + behavior_reasons + scoring_result["reason"]))
        severity = str(scoring_result["severity"])
        response_action = self._response_action(risk_score)
        story = build_attack_story(normalized_event, triggers, response_action, severity)
        alert_payload = self.alerts.generate(normalized_event, scoring_result)

        assessment = RiskAssessment(
            timestamp=str(normalized_event.get("timestamp") or datetime.utcnow().isoformat()),
            user=str(normalized_event.get("user", "unknown")),
            source=str(normalized_event.get("source", "unknown")),
            event_type=str(normalized_event.get("event_type", "unknown")),
            risk_score=round(risk_score, 2),
            severity=severity,
            response_action=response_action,
            ml_prediction=round(ml_prediction, 4),
            anomaly_score=round(anomaly_score, 4),
            rule_engine_score=round(rule_score, 4),
            behavior_score=round(behavior_score, 4),
            triggers=triggers,
            story=story,
            message=str(normalized_event.get("message", "")),
        )

        if persist:
            append_jsonl(CONFIG.incident_store, {**normalized_event, **assessment.to_dict(), **alert_payload})
            self.incidents.process_event({**normalized_event, **assessment.to_dict()}, persist=True)
        return assessment

    @staticmethod
    def _response_action(score: float) -> str:
        if score >= 85:
            return "Block process (simulation only)"
        if score >= 60:
            return "Restrict actions (log only)"
        if score >= 30:
            return "Alert"
        return "Monitor"


def latest_incidents(limit: int = 200) -> list[dict[str, Any]]:
    return read_jsonl(CONFIG.incident_store, limit=limit)
