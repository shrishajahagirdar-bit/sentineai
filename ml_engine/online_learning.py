from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any

import numpy as np
from sklearn.linear_model import SGDClassifier
from sklearn.preprocessing import StandardScaler

from ml_engine.drift_detector import DriftDetector, DriftState


@dataclass
class OnlinePrediction:
    ml_score: float
    prediction: str
    predicted_label: int
    model_version: int


@dataclass
class OnlineUpdateResult:
    updated: bool
    model_version: int
    drift_detected: bool
    fallback_triggered: bool
    baseline_error: float
    recent_error: float
    message: str


class OnlineLearningEngine:
    def __init__(self, feature_order: list[str] | None = None) -> None:
        self.feature_order = feature_order or []
        self.scaler = StandardScaler()
        self.model = SGDClassifier(loss="log_loss", random_state=42)
        self.classes = np.array([0, 1], dtype=int)
        self.is_initialized = False
        self.model_version = 1
        self.last_stable_state: dict[str, Any] | None = None
        self.drift_detector = DriftDetector()

    def _vectorize(self, features: dict[str, float]) -> np.ndarray:
        if not self.feature_order:
            self.feature_order = list(features.keys())
        row = [float(features.get(name, 0.0) or 0.0) for name in self.feature_order]
        return np.asarray([row], dtype=float)

    def predict(self, features: dict[str, float]) -> OnlinePrediction:
        vector = self._vectorize(features)
        if not self.is_initialized:
            score = float(
                np.clip(
                    (features.get("severity_score", 0.0) * 0.35)
                    + (features.get("request_rate", 0.0) * 0.25)
                    + (features.get("attack_weight", 0.0) * 0.40),
                    0.0,
                    1.0,
                )
            )
            predicted_label = 1 if score >= 0.5 else 0
            return OnlinePrediction(
                ml_score=round(score, 4),
                prediction="anomaly" if predicted_label == 1 else "normal",
                predicted_label=predicted_label,
                model_version=self.model_version,
            )

        scaled = self.scaler.transform(vector)
        probabilities = self.model.predict_proba(scaled)[0]
        score = float(probabilities[1])
        predicted_label = int(score >= 0.5)
        return OnlinePrediction(
            ml_score=round(score, 4),
            prediction="anomaly" if predicted_label == 1 else "normal",
            predicted_label=predicted_label,
            model_version=self.model_version,
        )

    def update(self, features: dict[str, float], label: int) -> OnlineUpdateResult:
        vector = self._vectorize(features)
        target = np.asarray([int(label)], dtype=int)
        prediction = self.predict(features)

        if not self.is_initialized:
            self.scaler.partial_fit(vector)
            scaled = self.scaler.transform(vector)
            self.model.partial_fit(scaled, target, classes=self.classes)
            self.is_initialized = True
            self.last_stable_state = self._snapshot_state()
            return OnlineUpdateResult(
                updated=True,
                model_version=self.model_version,
                drift_detected=False,
                fallback_triggered=False,
                baseline_error=0.0,
                recent_error=0.0,
                message="online model initialized",
            )

        self.scaler.partial_fit(vector)
        scaled = self.scaler.transform(vector)
        self.model.partial_fit(scaled, target)
        drift_state = self.drift_detector.update(target[0], prediction.predicted_label)

        fallback_triggered = False
        if drift_state.drift_detected and self.last_stable_state is not None:
            self._restore_state(self.last_stable_state)
            fallback_triggered = True
        elif not drift_state.drift_detected:
            self.last_stable_state = self._snapshot_state()
            self.model_version += 1

        return OnlineUpdateResult(
            updated=True,
            model_version=self.model_version,
            drift_detected=drift_state.drift_detected,
            fallback_triggered=fallback_triggered,
            baseline_error=drift_state.baseline_error,
            recent_error=drift_state.recent_error,
            message="reverted to last stable model" if fallback_triggered else drift_state.message,
        )

    def _snapshot_state(self) -> dict[str, Any]:
        return {
            "scaler": deepcopy(self.scaler),
            "model": deepcopy(self.model),
            "is_initialized": self.is_initialized,
            "model_version": self.model_version,
            "feature_order": list(self.feature_order),
        }

    def _restore_state(self, state: dict[str, Any]) -> None:
        self.scaler = deepcopy(state["scaler"])
        self.model = deepcopy(state["model"])
        self.is_initialized = bool(state["is_initialized"])
        self.model_version = int(state["model_version"])
        self.feature_order = list(state["feature_order"])
