from __future__ import annotations

from typing import Any

from agent.core.schema import EndpointEvent
from core.schema import CanonicalEvent
from core.validator import validate_model


class SchemaRegistry:
    def validate(self, schema_name: str, payload: dict[str, Any]) -> dict[str, Any]:
        if schema_name == "endpoint_event":
            return validate_model(payload, EndpointEvent, fallback={"event_type": "fallback"})
        return validate_model(payload, CanonicalEvent, fallback={"event_type": "fallback"})

    def require_tenant(self, payload: dict[str, Any]) -> dict[str, Any]:
        tenant_id = payload.get("tenant_id")
        if tenant_id:
            return payload
        metadata = payload.get("metadata", {})
        if isinstance(metadata, dict) and metadata.get("tenant_id"):
            payload["tenant_id"] = metadata["tenant_id"]
            return payload
        raise ValueError("tenant_id is required for tenant-aware Kafka routing")


schema_registry = SchemaRegistry()
