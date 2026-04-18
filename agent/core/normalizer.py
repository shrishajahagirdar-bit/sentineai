from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from agent.core.config import AgentConfig
from agent.core.schema import EndpointEvent


def _timestamp(value: Any | None = None) -> str:
    if value is None:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(value, str):
        return value
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return datetime.now(timezone.utc).isoformat()


def build_event(
    config: AgentConfig,
    *,
    user: str = "unknown",
    event_source: str,
    event_type: str,
    severity: str = "low",
    raw_data: dict[str, Any] | None = None,
    process_name: str = "",
    pid: int = 0,
    cpu: float = 0.0,
    memory: int = 0,
    network: dict[str, Any] | None = None,
    event_log_id: str = "",
    timestamp: str | None = None,
) -> dict[str, Any]:
    payload = EndpointEvent(
        timestamp=timestamp or _timestamp(),
        tenant_id=config.tenant_id or "unknown",
        agent_id=config.agent_id or "unknown",
        host=config.hostname,
        machine_id=config.machine_id,
        session_name=config.session_name,
        user=user or "unknown",
        event_source=event_source,  # type: ignore[arg-type]
        event_type=event_type,
        severity=severity,  # type: ignore[arg-type]
        raw_data=raw_data or {},
        process_name=process_name or "",
        pid=int(pid or 0),
        cpu=float(cpu or 0.0),
        memory=int(memory or 0),
        network=network or {},
        event_log_id=event_log_id,
        ml_score=0.0,
    )
    return payload.model_dump()


def heartbeat_event(config: AgentConfig, *, queue_depth: int) -> dict[str, Any]:
    return build_event(
        config,
        user="system",
        event_source="heartbeat",
        event_type="agent_heartbeat",
        severity="low",
        raw_data={
            "agent_name": config.agent_name,
            "queue_depth": queue_depth,
            "status": "healthy",
        },
    )
