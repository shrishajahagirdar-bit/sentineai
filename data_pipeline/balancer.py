from __future__ import annotations

import random
from typing import Any

from validation.labels import normalize_label


def balance_dataset(events: list[dict[str, Any]], *, seed: int = 42) -> list[dict[str, Any]]:
    normal_events = [dict(event) for event in events if normalize_label(event) == 0]
    anomaly_events = [dict(event) for event in events if normalize_label(event) == 1]

    if not normal_events or not anomaly_events:
        return []

    sample_size = min(len(normal_events), len(anomaly_events))
    rng = random.Random(seed)

    balanced = rng.sample(normal_events, sample_size) + rng.sample(anomaly_events, sample_size)
    rng.shuffle(balanced)
    return balanced


def balance_features_and_labels(
    features: Any,
    labels: Any,
    *,
    seed: int = 42,
):
    import pandas as pd

    feature_frame = pd.DataFrame(features).reset_index(drop=True)
    label_series = pd.Series(labels).astype(int).reset_index(drop=True)

    normal_idx = label_series[label_series == 0].index.tolist()
    anomaly_idx = label_series[label_series == 1].index.tolist()
    if not normal_idx or not anomaly_idx:
        return feature_frame.iloc[0:0].copy(), label_series.iloc[0:0].copy()

    sample_size = min(len(normal_idx), len(anomaly_idx))
    rng = random.Random(seed)
    selected_idx = rng.sample(normal_idx, sample_size) + rng.sample(anomaly_idx, sample_size)
    rng.shuffle(selected_idx)

    balanced_x = feature_frame.loc[selected_idx].reset_index(drop=True)
    balanced_y = label_series.loc[selected_idx].reset_index(drop=True)
    return balanced_x, balanced_y
