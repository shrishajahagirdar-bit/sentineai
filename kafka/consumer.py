from __future__ import annotations

import json
from typing import Any

from collector.storage import append_jsonl
from core.schema import CanonicalEvent
from core.safe_wrapper import log_health_event, safe_execution
from core.validator import validate_model
from kafka.producer import consume_from_memory
from kafka.schema_registry import schema_registry
from pipeline.stream_processor import StreamProcessor
from observability.metrics import DLQ_RATE, FAILED_EVENT_COUNT, KAFKA_LAG, SERVICE_HEALTH
from resiliency.circuit_breaker import CircuitBreaker
from resiliency.retry import with_retry
from sentinel_config import CONFIG

try:
    from confluent_kafka import Consumer as ConfluentConsumer
except ImportError:  # pragma: no cover
    ConfluentConsumer = None


class SecurityLogsConsumer:
    def __init__(self, bootstrap_servers: list[str] | None = None, topic: str | None = None, group_id: str | None = None) -> None:
        self.bootstrap_servers = bootstrap_servers or ["localhost:9092"]
        self.topic = topic or CONFIG.kafka_tenant_topic
        self.group_id = group_id or CONFIG.kafka_consumer_group
        self.processor = StreamProcessor()
        self.breaker = CircuitBreaker(failure_threshold=3, recovery_timeout_seconds=30.0)
        self.processed_ids: set[str] = set()
        self._client = self._build_client()

    @safe_execution(default_factory=list, operation="kafka_consumer_poll")
    def poll(self, max_messages: int = 100) -> list[dict[str, Any]]:
        processed: list[dict[str, Any]] = []
        messages = self._poll_messages(max_messages=max_messages)
        if not messages:
            return []

        for message in messages:
            try:
                normalized = schema_registry.require_tenant(schema_registry.validate("canonical_event", message))
            except Exception as exc:
                append_jsonl(CONFIG.dead_letter_store, {**message, "dlq_reason": str(exc)})
                DLQ_RATE.labels(tenant_id=str(message.get("tenant_id", "unknown"))).inc()
                continue
            event_id = str(normalized.get("event_id", ""))
            if event_id and event_id in self.processed_ids:
                continue
            try:
                if not self.breaker.allow():
                    raise RuntimeError("Kafka consumer circuit open")
                processed.append(with_retry(lambda: self.processor.process_event(normalized, persist=True), attempts=2, base_delay=0.1, factor=2.0))
                if event_id:
                    self.processed_ids.add(event_id)
                self.breaker.record_success()
            except Exception as exc:
                self.breaker.record_failure()
                log_health_event(
                    "error",
                    "kafka_consumer_poll",
                    "Event processing failed; sending to dead-letter store.",
                    context={"error": str(exc), "event_id": normalized.get("event_id")},
                )
                append_jsonl(CONFIG.dead_letter_store, {**normalized, "dlq_reason": str(exc)})
                tenant_id = str(normalized.get("tenant_id", "unknown"))
                FAILED_EVENT_COUNT.labels(tenant_id=tenant_id, component="kafka_consumer").inc()
                DLQ_RATE.labels(tenant_id=tenant_id).inc()
        return processed

    def _build_client(self) -> Any | None:
        if not CONFIG.kafka_use_real_broker or ConfluentConsumer is None:
            return None
        try:
            client = ConfluentConsumer(
                {
                    "bootstrap.servers": ",".join(self.bootstrap_servers),
                    "group.id": self.group_id,
                    "auto.offset.reset": "latest",
                    "enable.auto.commit": True,
                }
            )
            client.subscribe([self.topic])
            SERVICE_HEALTH.labels(service="kafka-consumer").set(1)
            return client
        except Exception as exc:
            log_health_event(
                "warning",
                "kafka_consumer_init",
                "Kafka broker unavailable; using in-memory transport.",
                context={"error": str(exc), "bootstrap_servers": self.bootstrap_servers},
            )
            SERVICE_HEALTH.labels(service="kafka-consumer").set(0)
            return None

    def _poll_messages(self, max_messages: int) -> list[dict[str, Any]]:
        if self._client is None:
            return consume_from_memory(self.topic, max_messages=max_messages)

        messages: list[dict[str, Any]] = []
        for _ in range(max_messages):
            msg = self._client.poll(CONFIG.kafka_poll_timeout_seconds)
            if msg is None:
                break
            if msg.error():
                log_health_event(
                    "warning",
                    "kafka_consumer_poll",
                    "Kafka consumer returned an error.",
                    context={"error": str(msg.error())},
                )
                continue
            try:
                payload = json.loads(msg.value().decode("utf-8"))
            except Exception as exc:
                log_health_event(
                    "warning",
                    "kafka_consumer_decode",
                    "Unable to decode Kafka payload.",
                    context={"error": str(exc)},
                )
                continue
            if isinstance(payload, dict):
                messages.append(payload)
                KAFKA_LAG.labels(tenant_id=str(payload.get("tenant_id", "unknown")), topic=self.topic).set(max(len(messages) - 1, 0))
        return messages
