from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_event_id() -> str:
    return str(uuid4())


class StandardResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: Literal["success", "error", "fallback"] = "fallback"
    data: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class MLOutputSchema(BaseModel):
    model_config = ConfigDict(extra="allow")

    user: str = "unknown"
    risk_score: float = 0.0
    prediction: str = "unknown"
    anomaly_score: float = 0.0
    timestamp: str = Field(default_factory=_utc_now_iso)
    status: str = "safe_fallback"
    message: str = "data unavailable"
    metadata: dict[str, Any] = Field(default_factory=dict)


class LogEventSchema(BaseModel):
    model_config = ConfigDict(extra="allow")

    time: str = Field(default_factory=_utc_now_iso)
    user: str = "unknown"
    activity: str = "unknown"
    device: str = "unknown"
    location: str = "unknown"
    failed_attempts: int = 0
    cpu_usage: float = 0.0


class UIDataSchema(BaseModel):
    model_config = ConfigDict(extra="ignore")

    metrics: dict[str, Any] = Field(default_factory=dict)
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    logs: list[dict[str, Any]] = Field(default_factory=list)
    risk_trend: list[dict[str, Any]] = Field(default_factory=list)
    status: str = "safe_fallback"
    message: str = "data unavailable"


class CanonicalEvent(BaseModel):
    model_config = ConfigDict(extra="allow")

    event_id: str = Field(default_factory=_default_event_id)
    timestamp: str = Field(default_factory=_utc_now_iso)
    hostname: str = "unknown"
    source: str = "unknown"
    event_type: str = "unknown"
    severity: Literal["low", "medium", "high", "critical"] = "low"
    raw_log: str = ""
    parsed_fields: dict[str, Any] = Field(default_factory=dict)
    ml_score: float = 0.0
    ml_prediction: str = "unknown"
    metadata: dict[str, Any] = Field(default_factory=dict)
    user: str = "unknown"
    message: str = "data unavailable"
    risk_score: float = 0.0
    anomaly_score: float = 0.0
    status: str = "safe_fallback"
    label: int = 0
    attack_type: str = "none"

    @model_validator(mode="before")
    @classmethod
    def _normalize_input(cls, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            return {}

        payload = dict(value)
        metadata = payload.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {"original_metadata": metadata}

        parsed_fields = payload.get("parsed_fields", {})
        if not isinstance(parsed_fields, dict):
            parsed_fields = {}

        aliases = {
            "user_id": "user",
            "prediction": "ml_prediction",
            "anomaly_prediction": "ml_prediction",
            "time": "timestamp",
            "host": "hostname",
            "computer_name": "hostname",
        }
        for source_key, target_key in aliases.items():
            if source_key in payload and target_key not in payload:
                payload[target_key] = payload[source_key]

        raw_value = payload.get("raw_log", payload.get("raw", payload.get("message", "")))
        if isinstance(raw_value, dict):
            parsed_fields = {**raw_value, **parsed_fields}
            payload["raw_log"] = str(raw_value.get("message", payload.get("message", "")))
        else:
            payload["raw_log"] = str(raw_value or "")

        risk_value = payload.get("risk_score", payload.get("ml_score", 0.0))
        payload["risk_score"] = risk_value
        payload["ml_score"] = payload.get("ml_score", risk_value)
        payload["anomaly_score"] = payload.get("anomaly_score", 0.0)
        payload["message"] = str(payload.get("message", payload.get("incident_story", "data unavailable")))
        payload["status"] = str(payload.get("status", "success"))
        payload["label"] = int(payload.get("label", 0) or 0)
        payload["attack_type"] = str(payload.get("attack_type", payload.get("metadata", {}).get("attack_type", "none")))
        payload["hostname"] = str(payload.get("hostname", "unknown"))

        known_fields = set(cls.model_fields.keys())
        extras = {key: val for key, val in payload.items() if key not in known_fields}
        if extras:
            metadata = {**extras, **metadata}
        payload["metadata"] = metadata
        payload["parsed_fields"] = {**parsed_fields, **payload.get("raw_features", {})}

        severity = str(payload.get("severity", "")).lower()
        if severity not in {"low", "medium", "high", "critical"}:
            score = payload.get("risk_score", 0.0)
            try:
                numeric_score = float(score)
            except (TypeError, ValueError):
                numeric_score = 0.0
            if numeric_score >= 85:
                payload["severity"] = "critical"
            elif numeric_score >= 60:
                payload["severity"] = "high"
            elif numeric_score >= 30:
                payload["severity"] = "medium"
            else:
                payload["severity"] = "low"

        return payload


class EventStoreEnvelope(BaseModel):
    model_config = ConfigDict(extra="ignore")

    events: list[CanonicalEvent] = Field(default_factory=list)
    status: str = "safe_fallback"
    source: str = "unknown"


class IncidentSchema(BaseModel):
    model_config = ConfigDict(extra="allow")

    incident_id: str = Field(default_factory=_default_event_id)
    start_time: str = Field(default_factory=_utc_now_iso)
    end_time: str = Field(default_factory=_utc_now_iso)
    severity: Literal["low", "medium", "high", "critical"] = "low"
    status: Literal["open", "investigating", "resolved"] = "open"
    related_event_ids: list[str] = Field(default_factory=list)
    attack_type: str = "unknown"
    risk_score: float = 0.0
    summary: str = "data unavailable"
    user: str = "unknown"
    source: str = "unknown"
    metadata: dict[str, Any] = Field(default_factory=dict)
