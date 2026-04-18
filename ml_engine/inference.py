from __future__ import annotations

from typing import Any

import joblib
import numpy as np

from core.safe_wrapper import safe_execution
from core.transformers import normalize_ml_output
from ml_engine.features import events_to_frame
from observability.metrics import ML_INFERENCE_LATENCY, SERVICE_HEALTH
from resiliency.circuit_breaker import CircuitBreaker
from sentinel_config import CONFIG


class LiveModelEngine:
    def __init__(self) -> None:
        self.package = self._load()
        self.breaker = CircuitBreaker(failure_threshold=3, recovery_timeout_seconds=30.0)

    def _load(self) -> dict[str, Any] | None:
        if not CONFIG.model_store.exists():
            return None
        try:
            return joblib.load(CONFIG.model_store)
        except Exception:
            return None

    def reload(self) -> None:
        self.package = self._load()

    @safe_execution(default_factory=lambda: normalize_ml_output({}, user="unknown"), operation="ml_predict_output")
    def predict_output(self, event: dict[str, Any]) -> dict[str, Any]:
        probability, anomaly_score = self.predict(event)
        return normalize_ml_output(
            {
                "user": event.get("user", "unknown"),
                "risk_score": probability,
                "prediction": "anomaly" if probability >= 0.5 else "normal",
                "anomaly_score": anomaly_score,
                "timestamp": event.get("timestamp"),
                "status": "success",
                "message": "ml inference completed",
                "metadata": {
                    "source": event.get("source", "unknown"),
                    "event_type": event.get("event_type", "unknown"),
                },
            },
            user=str(event.get("user", "unknown")),
        )

    def predict(self, event: dict[str, Any]) -> tuple[float, float]:
        with ML_INFERENCE_LATENCY.time():
            return self._predict_internal(event)

    def _predict_internal(self, event: dict[str, Any]) -> tuple[float, float]:
        if not self.breaker.allow():
            SERVICE_HEALTH.labels(service="ml-inference").set(0)
            return self._heuristic_prediction(event), self._heuristic_anomaly(event)
        if self.package is None:
            SERVICE_HEALTH.labels(service="ml-inference").set(0)
            return self._heuristic_prediction(event), self._heuristic_anomaly(event)

        frame = events_to_frame([event])
        frame = frame.reindex(columns=self.package["feature_columns"], fill_value=0.0)

        classifier = self.package["classifier"]
        anomaly_model = self.package["anomaly_model"]

        try:
            probability = float(classifier.predict_proba(frame)[0][1])
            self.breaker.record_success()
        except Exception:
            self.breaker.record_failure()
            probability = self._heuristic_prediction(event)

        try:
            raw_score = float(anomaly_model.decision_function(frame)[0])
            anomaly_score = float(np.clip(0.5 - raw_score, 0.0, 1.0))
            self.breaker.record_success()
        except Exception:
            self.breaker.record_failure()
            anomaly_score = self._heuristic_anomaly(event)

        SERVICE_HEALTH.labels(service="ml-inference").set(1 if self.breaker.allow() else 0)
        return probability, anomaly_score

    @staticmethod
    def _heuristic_prediction(event: dict[str, Any]) -> float:
        score = 0.0
        score += 0.35 if event.get("unknown_process") else 0.0
        score += 0.25 if event.get("unusual_network_ip") else 0.0
        score += 0.25 if event.get("sensitive_file_access") else 0.0
        score += 0.15 if event.get("event_type") == "login_failure" else 0.0
        return min(score, 1.0)

    @staticmethod
    def _heuristic_anomaly(event: dict[str, Any]) -> float:
        score = 0.0
        score += 0.30 if event.get("unknown_process") else 0.0
        score += 0.30 if event.get("suspicious_port") else 0.0
        score += 0.20 if event.get("unusual_network_ip") else 0.0
        score += 0.20 if event.get("sensitive_file_access") else 0.0
        return min(score, 1.0)
