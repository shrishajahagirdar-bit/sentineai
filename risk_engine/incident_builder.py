from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from collector.storage import append_jsonl
from core.safe_wrapper import safe_execution
from core.schema import IncidentSchema
from core.transformers import normalize_event
from core.validator import validate_model
from sentinel_config import CONFIG


def _parse_timestamp(value: Any) -> datetime:
    text = str(value or datetime.now(timezone.utc).isoformat())
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def _score_to_severity(score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


@dataclass
class IncidentState:
    incident_id: str
    correlation_key: str
    start_time: datetime
    end_time: datetime
    related_event_ids: list[str] = field(default_factory=list)
    risk_scores: list[float] = field(default_factory=list)
    severities: list[str] = field(default_factory=list)
    users: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    event_types: set[str] = field(default_factory=set)
    triggers: set[str] = field(default_factory=set)
    status: str = "open"


class IncidentBuilder:
    def __init__(self, window_minutes: int | None = None) -> None:
        self.window = timedelta(minutes=window_minutes or CONFIG.incident_window_minutes)
        self.active: dict[str, IncidentState] = {}

    @safe_execution(default_factory=lambda: None, operation="incident_builder_process")
    def process_event(self, raw_event: dict[str, Any], persist: bool = True) -> dict[str, Any] | None:
        event = normalize_event(raw_event)
        risk_score = float(event.get("risk_score", 0.0) or 0.0)
        severity = str(event.get("severity", _score_to_severity(risk_score)))

        if risk_score < 30 and severity not in {"high", "critical"}:
            return None

        now = _parse_timestamp(event.get("timestamp"))
        self._expire_old(now)
        correlation_key = self._correlation_key(event)
        state = self.active.get(correlation_key)

        if state is None:
            incident_seed = validate_model(
                {
                    "start_time": now.isoformat(),
                    "end_time": now.isoformat(),
                    "severity": severity,
                    "status": "open",
                    "related_event_ids": [],
                    "attack_type": self._attack_type(event),
                    "risk_score": risk_score / 100.0,
                    "summary": "Incident correlation in progress",
                    "user": event.get("user", "unknown"),
                    "source": event.get("source", "unknown"),
                    "metadata": {"correlation_key": correlation_key},
                },
                IncidentSchema,
            )
            state = IncidentState(
                incident_id=str(incident_seed["incident_id"]),
                correlation_key=correlation_key,
                start_time=now,
                end_time=now,
            )
            self.active[correlation_key] = state

        self._update_state(state, event, risk_score, severity, now)
        incident = self._build_incident(state)
        if persist:
            append_jsonl(CONFIG.incident_case_store, incident)
        return incident

    def replay(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        incidents: list[dict[str, Any]] = []
        for event in events:
            incident = self.process_event(event, persist=False)
            if incident is not None:
                incidents.append(incident)
        return incidents

    def _expire_old(self, current_time: datetime) -> None:
        expired = [
            key for key, state in self.active.items()
            if current_time - state.end_time > self.window
        ]
        for key in expired:
            self.active.pop(key, None)

    def _correlation_key(self, event: dict[str, Any]) -> str:
        attack_type = self._attack_type(event)
        user = str(event.get("user", "unknown"))
        source = str(event.get("source", "unknown"))
        device = str(event.get("metadata", {}).get("device_id", event.get("device_id", "unknown")))
        return "|".join([attack_type, user, source, device])

    def _attack_type(self, event: dict[str, Any]) -> str:
        event_type = str(event.get("event_type", "")).lower()
        message = str(event.get("message", "")).lower()
        triggers = " ".join([str(item).lower() for item in event.get("triggers", [])])

        if "login_failure" in event_type or "failed login" in message:
            return "bruteforce"
        if "port" in message or "suspicious_port" in triggers:
            return "port_scan"
        if "process" in event_type or "unknown process" in triggers:
            return "suspicious_process"
        if "network" in event_type or "unusual network" in triggers:
            return "lateral_movement"
        if float(event.get("anomaly_score", 0.0) or 0.0) > 0.5:
            return "anomaly"
        return "unknown"

    def _update_state(self, state: IncidentState, event: dict[str, Any], risk_score: float, severity: str, now: datetime) -> None:
        state.end_time = now
        event_id = str(event.get("event_id", ""))
        if event_id and event_id not in state.related_event_ids:
            state.related_event_ids.append(event_id)
        state.risk_scores.append(risk_score)
        state.severities.append(severity)
        state.users.add(str(event.get("user", "unknown")))
        state.sources.add(str(event.get("source", "unknown")))
        state.event_types.add(str(event.get("event_type", "unknown")))
        for trigger in event.get("triggers", []):
            state.triggers.add(str(trigger))

    def _build_incident(self, state: IncidentState) -> dict[str, Any]:
        max_score = max(state.risk_scores, default=0.0)
        severity = max(state.severities, key=lambda item: ["low", "medium", "high", "critical"].index(item), default="low")
        attack_type = state.correlation_key.split("|", 1)[0]
        summary = self._summary(state, attack_type, severity, max_score)
        return validate_model(
            {
                "incident_id": state.incident_id,
                "start_time": state.start_time.isoformat(),
                "end_time": state.end_time.isoformat(),
                "severity": severity,
                "status": state.status,
                "related_event_ids": state.related_event_ids,
                "attack_type": attack_type,
                "risk_score": round(max_score / 100.0, 4),
                "summary": summary,
                "user": next(iter(state.users), "unknown"),
                "source": next(iter(state.sources), "unknown"),
                "metadata": {
                    "event_types": sorted(state.event_types),
                    "triggers": sorted(state.triggers),
                    "event_count": len(state.related_event_ids),
                },
            },
            IncidentSchema,
        )

    def _summary(self, state: IncidentState, attack_type: str, severity: str, max_score: float) -> str:
        user = next(iter(state.users), "unknown")
        trigger_text = ", ".join(sorted(state.triggers)) if state.triggers else "correlated anomalies"
        return (
            f"{attack_type.replace('_', ' ').title()} activity correlated for user {user}. "
            f"{len(state.related_event_ids)} events were grouped between "
            f"{state.start_time.isoformat()} and {state.end_time.isoformat()} with "
            f"{severity} severity and peak risk score {max_score:.1f}. Indicators: {trigger_text}."
        )
