from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone


class BehavioralCorrelationEngine:
    def __init__(self, window_seconds: int = 900) -> None:
        self.window_seconds = window_seconds
        self.timeline: dict[str, deque[dict]] = defaultdict(lambda: deque(maxlen=200))

    def ingest(self, event: dict) -> dict[str, object]:
        key = self._entity_key(event)
        ts = self._to_epoch(event.get("timestamp"))
        history = self.timeline[key]
        history.append({"timestamp": ts, "event_type": event.get("event_type"), "severity": event.get("severity")})
        related = [item for item in history if ts - item["timestamp"] <= self.window_seconds]
        event_types = {str(item["event_type"]) for item in related}
        suspicious_chain = {"login_failure", "process_create", "network_connection"}.issubset(event_types)
        return {
            "entity": key,
            "related_event_count": len(related),
            "event_types": sorted(event_types),
            "suspicious_chain": suspicious_chain,
        }

    @staticmethod
    def _entity_key(event: dict) -> str:
        host = str(event.get("hostname") or event.get("host") or "unknown-host")
        user = str(event.get("user") or "unknown-user")
        return f"{host}:{user}"

    @staticmethod
    def _to_epoch(value: object) -> float:
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
        except ValueError:
            return datetime.now(timezone.utc).timestamp()
