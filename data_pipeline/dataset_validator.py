from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from collector.storage import read_jsonl
from sentinel_config import CONFIG
from validation.labels import normalize_label


@dataclass
class DatasetValidationReport:
    total_events: int
    normal_count: int
    anomaly_count: int
    event_type_distribution: dict[str, int]
    label_distribution: dict[str, int]
    imbalance_ratio: float
    valid: bool
    message: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _training_eligible(event: dict[str, Any]) -> bool:
    return (
        event.get("status") == "ok"
        and event.get("source") != "file_monitor"
        and event.get("event_type") not in {"collector_status", "heartbeat"}
    )


def validate_telemetry_dataset(
    path: Path | None = None,
    *,
    imbalance_threshold: float = 0.20,
    min_events: int = 50,
) -> tuple[DatasetValidationReport, list[dict[str, Any]]]:
    dataset_path = path or CONFIG.event_store
    records = [event for event in read_jsonl(dataset_path, limit=None) if _training_eligible(event)]

    event_type_distribution = Counter(str(event.get("event_type", "unknown")).lower() for event in records)
    labels = [normalize_label(event) for event in records]
    label_distribution = Counter(labels)

    normal_count = int(label_distribution.get(0, 0))
    anomaly_count = int(label_distribution.get(1, 0))
    total_events = len(records)

    if max(normal_count, anomaly_count, 0) == 0:
        imbalance_ratio = 0.0
    else:
        imbalance_ratio = min(normal_count, anomaly_count) / max(normal_count, anomaly_count)

    valid = True
    message = "dataset validated"

    if total_events < min_events:
        valid = False
        message = f"Need at least {min_events} training events, found {total_events}."
    elif normal_count == 0 or anomaly_count == 0:
        valid = False
        message = "Training blocked: only one class exists after label normalization."
    elif imbalance_ratio < imbalance_threshold:
        valid = False
        message = (
            f"Training blocked: imbalance ratio {imbalance_ratio:.2f} is below "
            f"the threshold of {imbalance_threshold:.2f}."
        )

    report = DatasetValidationReport(
        total_events=total_events,
        normal_count=normal_count,
        anomaly_count=anomaly_count,
        event_type_distribution=dict(sorted(event_type_distribution.items())),
        label_distribution={"normal": normal_count, "anomaly": anomaly_count},
        imbalance_ratio=float(imbalance_ratio),
        valid=valid,
        message=message,
    )
    return report, records
