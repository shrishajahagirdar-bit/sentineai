from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from core.safe_wrapper import log_health_event, safe_execution
from core.transformers import normalize_event

try:
    from kafka import KafkaConsumer, KafkaProducer  # type: ignore
except ImportError:  # pragma: no cover
    KafkaConsumer = None
    KafkaProducer = None


class LogParser:
    @safe_execution(default_factory=dict, operation="kafka_log_parse")
    def parse(self, raw_message: bytes | str | dict[str, Any]) -> dict[str, Any]:
        if isinstance(raw_message, bytes):
            raw_message = raw_message.decode("utf-8", errors="ignore")
        if isinstance(raw_message, str):
            raw_message = json.loads(raw_message)
        if not isinstance(raw_message, dict):
            return {}
        return raw_message


class EventNormalizer:
    @safe_execution(default_factory=lambda: normalize_event({}), operation="kafka_event_normalize")
    def normalize(self, payload: dict[str, Any]) -> dict[str, Any]:
        return normalize_event(payload)


class ValidatedEventStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    @safe_execution(default_factory=lambda: None, operation="kafka_store_append")
    def append(self, event: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(normalize_event(event), default=str) + "\n")


class KafkaEventProducer:
    def __init__(self, bootstrap_servers: list[str], topic: str) -> None:
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.producer = None
        if KafkaProducer is not None:
            self.producer = KafkaProducer(
                bootstrap_servers=bootstrap_servers,
                value_serializer=lambda value: json.dumps(normalize_event(value)).encode("utf-8"),
            )

    @safe_execution(default_factory=lambda: False, operation="kafka_event_produce")
    def publish(self, event: dict[str, Any]) -> bool:
        if self.producer is None:
            log_health_event(
                "warning",
                "kafka_event_produce",
                "Kafka producer dependency is unavailable.",
                context={"topic": self.topic},
            )
            return False
        self.producer.send(self.topic, normalize_event(event))
        self.producer.flush()
        return True


class KafkaEventConsumer:
    def __init__(self, bootstrap_servers: list[str], topic: str, group_id: str, store: ValidatedEventStore) -> None:
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.group_id = group_id
        self.store = store
        self.parser = LogParser()
        self.normalizer = EventNormalizer()
        self.consumer = None
        if KafkaConsumer is not None:
            self.consumer = KafkaConsumer(
                topic,
                bootstrap_servers=bootstrap_servers,
                group_id=group_id,
                auto_offset_reset="latest",
                enable_auto_commit=True,
            )

    @safe_execution(default_factory=list, operation="kafka_consume_batch")
    def consume_batch(self, max_messages: int = 100) -> list[dict[str, Any]]:
        if self.consumer is None:
            log_health_event(
                "warning",
                "kafka_consume_batch",
                "Kafka consumer dependency is unavailable.",
                context={"topic": self.topic},
            )
            return []

        events: list[dict[str, Any]] = []
        for message in self.consumer:
            parsed = self.parser.parse(message.value)
            normalized = self.normalizer.normalize(parsed)
            self.store.append(normalized)
            events.append(normalized)
            if len(events) >= max_messages:
                break
        return events


def pipeline_stage_summary() -> list[str]:
    return [
        "Kafka Producer",
        "Kafka Consumer",
        "Log Parser",
        "ML Inference Engine",
        "Event Normalizer",
        "Validated Event Store",
        "Dashboard Layer",
    ]


def replay_events(records: Iterable[dict[str, Any]], store: ValidatedEventStore) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    normalizer = EventNormalizer()
    for record in records:
        event = normalizer.normalize(record)
        store.append(event)
        normalized.append(event)
    return normalized
