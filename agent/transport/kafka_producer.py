from __future__ import annotations

import time
from collections import deque
from typing import Any

from agent.core.config import AgentConfig
from observability.metrics import DLQ_RATE, EVENT_INGESTION_RATE, FAILED_EVENT_COUNT, KAFKA_LAG, SERVICE_HEALTH
from resiliency.circuit_breaker import CircuitBreaker
from resiliency.retry import with_retry
from resiliency.spool import JsonlSpool

try:
    from confluent_kafka import Producer as ConfluentProducer
except ImportError:  # pragma: no cover
    ConfluentProducer = None


class KafkaEventTransport:
    def __init__(self, config: AgentConfig, logger: Any) -> None:
        self.config = config
        self.logger = logger
        self.offline_buffer: deque[dict[str, Any]] = deque(maxlen=config.queue_maxsize)
        self.spool = JsonlSpool(config.spool_path)
        self.breaker = CircuitBreaker(failure_threshold=3, recovery_timeout_seconds=30.0)
        self.client = self._build_client()

    def send_batch(self, events: list[dict[str, Any]]) -> int:
        if not events:
            return 0

        pending = self.spool.drain(limit=self.config.queue_maxsize) + list(self.offline_buffer) + events
        self.offline_buffer.clear()
        sent = 0

        for event in pending:
            delivered = False
            for attempt in range(1, self.config.publisher_retries + 1):
                try:
                    if not self.breaker.allow():
                        raise RuntimeError("Kafka circuit open; using spool fallback")
                    with_retry(lambda: self._publish(event), attempts=2, base_delay=0.25, factor=2.0)
                    self.breaker.record_success()
                    delivered = True
                    sent += 1
                    tenant_id = str(event.get("tenant_id", "unknown"))
                    EVENT_INGESTION_RATE.labels(tenant_id=tenant_id, source=str(event.get("event_source", "agent"))).inc()
                    KAFKA_LAG.labels(tenant_id=tenant_id, topic=self.config.kafka_topic).set(max(len(self.offline_buffer), 0))
                    break
                except Exception as exc:
                    self.breaker.record_failure()
                    self.logger.warning(
                        "event publish retry",
                        extra={
                            "payload": {
                                "attempt": attempt,
                                "error": str(exc),
                                "topic": self.config.kafka_topic,
                            }
                        },
                    )
                    time.sleep(self.config.publisher_retry_backoff_seconds)

            if not delivered:
                self.offline_buffer.append(event)
                self.spool.append(event)
                tenant_id = str(event.get("tenant_id", "unknown"))
                FAILED_EVENT_COUNT.labels(tenant_id=tenant_id, component="agent_transport").inc()
                DLQ_RATE.labels(tenant_id=tenant_id).inc()

        if self.client is not None:
            self.client.flush(2.0)
            SERVICE_HEALTH.labels(service="agent-kafka-transport").set(1)
        return sent

    def _publish(self, event: dict[str, Any]) -> None:
        if self.client is None:
            raise RuntimeError("Kafka producer unavailable")
        payload = EndpointSerializer.dumps(event)
        tenant_key = str(event.get("tenant_id", self.config.tenant_id or "unknown"))
        self.client.produce(self.config.kafka_topic, payload, key=tenant_key.encode("utf-8"))
        self.client.poll(0)

    def _build_client(self) -> Any | None:
        if ConfluentProducer is None:
            self.logger.warning("confluent_kafka missing", extra={"payload": {"transport": "kafka"}})
            return None
        try:
            producer = ConfluentProducer(
                {
                    "bootstrap.servers": ",".join(self.config.kafka_bootstrap_servers),
                    "enable.idempotence": True,
                    "acks": "all",
                    "client.id": self.config.machine_id,
                }
            )
            SERVICE_HEALTH.labels(service="agent-kafka-transport").set(1)
            return producer
        except Exception as exc:
            self.logger.warning("kafka init failed", extra={"payload": {"transport": "kafka", "error": str(exc)}})
            SERVICE_HEALTH.labels(service="agent-kafka-transport").set(0)
            return None


class EndpointSerializer:
    @staticmethod
    def dumps(event: dict[str, Any]) -> bytes:
        import json

        return json.dumps(event, default=str).encode("utf-8")
