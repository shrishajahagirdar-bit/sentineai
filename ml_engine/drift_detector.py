from __future__ import annotations

from collections import deque
from dataclasses import dataclass


@dataclass
class DriftState:
    drift_detected: bool
    baseline_error: float
    recent_error: float
    message: str


class DriftDetector:
    def __init__(self, baseline_window: int = 100, recent_window: int = 25, drift_threshold: float = 0.20) -> None:
        self.baseline_window = baseline_window
        self.recent_window = recent_window
        self.drift_threshold = drift_threshold
        self.baseline_errors: deque[float] = deque(maxlen=baseline_window)
        self.recent_errors: deque[float] = deque(maxlen=recent_window)

    def update(self, expected_label: int, predicted_label: int) -> DriftState:
        error = 0.0 if int(expected_label) == int(predicted_label) else 1.0
        self.baseline_errors.append(error)
        self.recent_errors.append(error)

        baseline_error = sum(self.baseline_errors) / len(self.baseline_errors) if self.baseline_errors else 0.0
        recent_error = sum(self.recent_errors) / len(self.recent_errors) if self.recent_errors else 0.0
        drift_detected = (
            len(self.baseline_errors) >= max(10, self.baseline_window // 2)
            and len(self.recent_errors) >= max(5, self.recent_window // 2)
            and recent_error > baseline_error + self.drift_threshold
        )
        message = "concept drift detected" if drift_detected else "stable"
        return DriftState(
            drift_detected=drift_detected,
            baseline_error=round(baseline_error, 4),
            recent_error=round(recent_error, 4),
            message=message,
        )
