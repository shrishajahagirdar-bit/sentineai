from __future__ import annotations

import json
from pathlib import Path

try:
    from prometheus_client import Counter, Gauge, Histogram, generate_latest
except ImportError:  # pragma: no cover
    class _Metric:
        def labels(self, **_: str):
            return self

        def inc(self, amount: float = 1.0) -> None:
            return

        def set(self, value: float) -> None:
            return

        def time(self):
            class _Timer:
                def __enter__(self):  # noqa: ANN001
                    return self

                def __exit__(self, exc_type, exc, tb):  # noqa: ANN001
                    return False

            return _Timer()

    def Counter(*args, **kwargs):  # type: ignore[override]
        return _Metric()

    def Gauge(*args, **kwargs):  # type: ignore[override]
        return _Metric()

    def Histogram(*args, **kwargs):  # type: ignore[override]
        return _Metric()

    def generate_latest() -> bytes:
        return b""


METRIC_SNAPSHOT_PATH = Path(__file__).resolve().parents[1] / "storage" / "observability" / "metrics_snapshot.json"

EVENT_INGESTION_RATE = Counter("sentinelai_event_ingested_total", "Events ingested", ["tenant_id", "source"])
FAILED_EVENT_COUNT = Counter("sentinelai_failed_events_total", "Failed events", ["tenant_id", "component"])
DLQ_RATE = Counter("sentinelai_dlq_total", "Dead-letter events", ["tenant_id"])
ML_INFERENCE_LATENCY = Histogram("sentinelai_ml_inference_latency_seconds", "ML inference latency")
AGENT_HEARTBEAT_HEALTH = Gauge("sentinelai_agent_heartbeat_health", "Agent health gauge", ["tenant_id", "agent_id"])
KAFKA_LAG = Gauge("sentinelai_kafka_lag", "Kafka lag per tenant", ["tenant_id", "topic"])
SERVICE_HEALTH = Gauge("sentinelai_service_health", "Service health", ["service"])


def export_prometheus() -> bytes:
    return generate_latest()


def write_snapshot(snapshot: dict) -> None:
    METRIC_SNAPSHOT_PATH.parent.mkdir(parents=True, exist_ok=True)
    METRIC_SNAPSHOT_PATH.write_text(json.dumps(snapshot, indent=2, default=str), encoding="utf-8")


def read_snapshot() -> dict:
    try:
        if METRIC_SNAPSHOT_PATH.exists():
            return json.loads(METRIC_SNAPSHOT_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return {}
