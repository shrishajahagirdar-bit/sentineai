from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class EndpointEvent(BaseModel):
    model_config = ConfigDict(extra="allow")

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: str = Field(default_factory=utc_now_iso)
    tenant_id: str = "unknown"
    agent_id: str = "unknown"
    host: str = "unknown"
    machine_id: str = "unknown"
    session_name: str = "unknown"
    user: str = "unknown"
    event_source: Literal["process", "network", "windows_event", "heartbeat"] = "process"
    event_type: str = "unknown"
    severity: Literal["low", "medium", "high", "critical"] = "low"
    raw_data: dict[str, Any] = Field(default_factory=dict)
    process_name: str = ""
    pid: int = 0
    cpu: float = 0.0
    memory: int = 0
    network: dict[str, Any] = Field(default_factory=dict)
    event_log_id: str = ""
    ml_score: float = 0.0
