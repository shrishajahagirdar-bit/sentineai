from __future__ import annotations

from datetime import datetime
from typing import Any

from collector.storage import read_jsonl
from core.safe_wrapper import safe_execution
from core.transformers import normalize_event
from sentinel_config import CONFIG


def _parse_timestamp(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


@safe_execution(default_factory=list, operation="replay_last_events")
def replay_last_events(limit: int = 100) -> list[dict[str, Any]]:
    return [normalize_event(record) for record in read_jsonl(CONFIG.event_store, limit=limit)]


@safe_execution(default_factory=list, operation="replay_time_range")
def replay_time_range(start_time: str, end_time: str, limit: int | None = None) -> list[dict[str, Any]]:
    start = _parse_timestamp(start_time)
    end = _parse_timestamp(end_time)
    if start is None or end is None:
        return []

    records = read_jsonl(CONFIG.event_store, limit=None)
    filtered: list[dict[str, Any]] = []
    for record in records:
        event = normalize_event(record)
        event_time = _parse_timestamp(event.get("timestamp"))
        if event_time is None:
            continue
        if start <= event_time <= end:
            filtered.append(event)

    return filtered[-limit:] if limit is not None else filtered


@safe_execution(default_factory=list, operation="replay_incident_events")
def replay_incident_events(incident_id: str) -> list[dict[str, Any]]:
    incident_records = read_jsonl(CONFIG.incident_case_store, limit=None)
    target = next((item for item in incident_records if str(item.get("incident_id")) == incident_id), None)
    if not isinstance(target, dict):
        return []

    related_ids = set(str(item) for item in target.get("related_event_ids", []))
    events = replay_last_events(limit=CONFIG.max_events)
    return [event for event in events if str(event.get("event_id")) in related_ids]
