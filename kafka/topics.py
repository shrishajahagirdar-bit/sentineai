from __future__ import annotations


class KafkaTopics:
    TENANT_EVENTS = "tenant-events"
    NORMALIZED_EVENTS = "normalized-events"
    SCORED_EVENTS = "scored-events"
    ALERTS = "alerts"
    RESPONSE_ACTIONS = "response-actions"
    DEAD_LETTER_QUEUE = "dead-letter-queue"

    @classmethod
    def all(cls) -> list[str]:
        return [
            cls.TENANT_EVENTS,
            cls.NORMALIZED_EVENTS,
            cls.SCORED_EVENTS,
            cls.ALERTS,
            cls.RESPONSE_ACTIONS,
            cls.DEAD_LETTER_QUEUE,
        ]
