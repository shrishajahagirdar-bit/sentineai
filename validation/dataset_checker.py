from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

import numpy as np


@dataclass
class DatasetCheckResult:
    total_samples: int
    normal_count: int
    anomaly_count: int
    anomaly_ratio: float
    feature_shape: tuple[int, ...]
    valid: bool
    warning: str | None = None
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def check_dataset(features: Any, labels: Any, *, minimum_samples: int = 50) -> DatasetCheckResult:
    x = np.asarray(features, dtype=float)
    y = np.asarray(labels, dtype=int)

    total_samples = int(len(y))
    anomaly_count = int((y == 1).sum())
    normal_count = int((y == 0).sum())
    anomaly_ratio = float(anomaly_count / total_samples) if total_samples else 0.0

    error = None
    warning = None
    valid = True

    if total_samples < minimum_samples:
        valid = False
        error = f"Need at least {minimum_samples} samples, found {total_samples}."
    elif normal_count == 0 or anomaly_count == 0:
        valid = False
        error = "Training requires both normal and anomaly classes."
    elif x.ndim != 2 or x.shape[0] != total_samples:
        valid = False
        error = "Feature matrix shape does not match label count."
    elif not np.isfinite(x).all():
        valid = False
        error = "Feature matrix contains non-finite values."

    if valid and anomaly_ratio < 0.20:
        warning = f"Anomaly ratio {anomaly_ratio:.2%} is below 20%; rebalancing required before training."

    return DatasetCheckResult(
        total_samples=total_samples,
        normal_count=normal_count,
        anomaly_count=anomaly_count,
        anomaly_ratio=anomaly_ratio,
        feature_shape=tuple(x.shape),
        valid=valid,
        warning=warning,
        error=error,
    )
