from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

from collector.storage import append_jsonl
from core.schema import CanonicalEvent
from core.safe_wrapper import log_health_event, safe_execution
from core.validator import validate_model
from kafka.schema_registry import schema_registry
from kafka.topics import KafkaTopics
from observability.metrics import DLQ_RATE, EVENT_INGESTION_RATE, FAILED_EVENT_COUNT, KAFKA_LAG, SERVICE_HEALTH
from resiliency.circuit_breaker import CircuitBreaker
from resiliency.retry import with_retry
from sentinel_config import CONFIG

try:
    from confluent_kafka import Producer as ConfluentProducer
except ImportError:  # pragma: no cover
    ConfluentProducer = None


_IN_MEMORY_TOPICS: dict[str, deque[dict[str, Any]]] = defaultdict(deque)


class SecurityLogsProducer:
    def __init__(self, bootstrap_servers: list[str] | None = None, topic: str | None = None) -> None:
        self.bootstrap_servers = bootstrap_servers or ["localhost:9092"]
        self.topic = topic or CONFIG.kafka_tenant_topic
        self.breaker = CircuitBreaker(failure_threshold=3, recovery_timeout_seconds=30.0)
        self._client = self._build_client()

    @safe_execution(default_factory=lambda: False, operation="kafka_producer_publish")
    def publish(self, event: dict[str, Any], *, topic: str | None = None, schema_name: str = "canonical_event") -> bool:
        normalized = schema_registry.validate(schema_name, event)
        try:
            route_topic = topic or self.topic
            try:
                normalized = schema_registry.require_tenant(normalized)
            except ValueError:
                if schema_name != "endpoint_event":
                    metadata = normalized.setdefault("metadata", {})
                    if isinstance(metadata, dict):
                        metadata.setdefault("tenant_id", "default")
                    normalized["tenant_id"] = metadata.get("tenant_id", "default")
                else:
                    raise
            if self._client is not None:
                key = str(normalized.get("tenant_id", "default")).encode("utf-8")
                if not self.breaker.allow():
                    raise RuntimeError("Kafka producer circuit open")
                with_retry(lambda: self._client.produce(route_topic, json_bytes(normalized), key=key), attempts=2, base_delay=0.1, factor=2.0)
                self._client.poll(0)
                self.breaker.record_success()
            else:
                _IN_MEMORY_TOPICS[route_topic].append(normalized)
            tenant_id = str(normalized.get("tenant_id", "default"))
            EVENT_INGESTION_RATE.labels(tenant_id=tenant_id, source=str(normalized.get("source", "unknown"))).inc()
            KAFKA_LAG.labels(tenant_id=tenant_id, topic=route_topic).set(len(_IN_MEMORY_TOPICS[route_topic]))
            return True
        except Exception as exc:
            self.breaker.record_failure()
            log_health_event(
                "error",
                "kafka_producer_publish",
                "Event publish failed; event moved to dead-letter store.",
                context={"topic": topic or self.topic, "error": str(exc)},
            )
            append_jsonl(CONFIG.dead_letter_store, {**normalized, "dlq_reason": str(exc)})
            _IN_MEMORY_TOPICS[KafkaTopics.DEAD_LETTER_QUEUE].append({**normalized, "dlq_reason": str(exc)})
            tenant_id = str(normalized.get("tenant_id", "default"))
            FAILED_EVENT_COUNT.labels(tenant_id=tenant_id, component="kafka_producer").inc()
            DLQ_RATE.labels(tenant_id=tenant_id).inc()
            return False

    @safe_execution(default_factory=lambda: 0, operation="kafka_producer_publish_batch")
    def publish_batch(self, events: list[dict[str, Any]], *, topic: str | None = None, schema_name: str = "canonical_event") -> int:
        published = 0
        for event in events:
            if self.publish(event, topic=topic, schema_name=schema_name):
                published += 1
        if self._client is not None:
            self._client.flush(2.0)
        return published

    def _build_client(self) -> Any | None:
        if not CONFIG.kafka_use_real_broker or ConfluentProducer is None:
            return None
        try:
            producer = ConfluentProducer({"bootstrap.servers": ",".join(self.bootstrap_servers)})
            SERVICE_HEALTH.labels(service="kafka-producer").set(1)
            return producer
        except Exception as exc:
            log_health_event(
                "warning",
                "kafka_producer_init",
                "Kafka broker unavailable; using in-memory transport.",
                context={"error": str(exc), "bootstrap_servers": self.bootstrap_servers},
            )
            SERVICE_HEALTH.labels(service="kafka-producer").set(0)
            return None


def json_bytes(event: dict[str, Any]) -> bytes:
    import json

    return json.dumps(event, default=str).encode("utf-8")


def consume_from_memory(topic: str, max_messages: int = 100) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    queue = _IN_MEMORY_TOPICS[topic]
    while queue and len(messages) < max_messages:
        messages.append(queue.popleft())
    return messages
