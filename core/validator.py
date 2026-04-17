from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ValidationError

from core.safe_wrapper import log_health_event


def safe_cast(value: Any, target_type: type[Any]) -> Any:
    if value is None:
        if target_type is str:
            return ""
        if target_type is int:
            return 0
        if target_type is float:
            return 0.0
        if target_type is bool:
            return False
        if target_type is dict:
            return {}
        if target_type is list:
            return []
        return None

    if isinstance(value, target_type):
        return value

    try:
        if target_type is bool:
            if isinstance(value, str):
                return value.strip().lower() in {"1", "true", "yes", "y", "on"}
            return bool(value)
        if target_type is int:
            return int(float(value))
        if target_type is float:
            return float(value)
        if target_type is str:
            return str(value)
        if target_type is dict:
            return value if isinstance(value, dict) else {}
        if target_type is list:
            return value if isinstance(value, list) else []
        return target_type(value)
    except (TypeError, ValueError):
        log_health_event(
            "warning",
            "safe_cast_failed",
            "Unable to cast value to requested type.",
            context={
                "target_type": getattr(target_type, "__name__", str(target_type)),
                "value_type": type(value).__name__,
            },
        )
        return safe_cast(None, target_type)


def fill_missing_fields(data: Any, defaults: dict[str, Any]) -> dict[str, Any]:
    payload = dict(data) if isinstance(data, dict) else {}
    for key, default_value in defaults.items():
        if key not in payload or payload[key] is None:
            payload[key] = default_value() if callable(default_value) else default_value
    return payload


def enforce_types(data: Any, schema: dict[str, type[Any]]) -> dict[str, Any]:
    payload = dict(data) if isinstance(data, dict) else {}
    normalized: dict[str, Any] = {}
    for key, target_type in schema.items():
        normalized[key] = safe_cast(payload.get(key), target_type)
    for key, value in payload.items():
        if key not in normalized:
            normalized[key] = value
    return normalized


def validate_model(data: Any, model_cls: type[BaseModel], fallback: dict[str, Any] | None = None) -> dict[str, Any]:
    fallback_payload = fallback or {}
    if data is None:
        log_health_event(
            "warning",
            "schema_validation_empty_payload",
            "Received null payload; returning fallback object.",
            context={"model": model_cls.__name__},
        )
        if fallback_payload:
            try:
                return model_cls.model_validate(fallback_payload).model_dump()
            except ValidationError:
                return fallback_payload
    try:
        model = model_cls.model_validate(data)
        return model.model_dump()
    except ValidationError as exc:
        log_health_event(
            "error",
            "schema_validation_failed",
            "Schema validation failed; returning fallback object.",
            context={
                "model": model_cls.__name__,
                "errors": exc.errors(),
            },
        )
        try:
            return model_cls.model_validate(fallback_payload).model_dump()
        except ValidationError:
            return fallback_payload


def validate_dict(
    data: Any,
    schema: dict[str, type[Any]] | type[BaseModel],
    defaults: dict[str, Any] | None = None,
    fallback: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = dict(data) if isinstance(data, dict) else {}
    if defaults:
        payload = fill_missing_fields(payload, defaults)

    if isinstance(schema, type) and issubclass(schema, BaseModel):
        return validate_model(payload, schema, fallback=fallback)

    normalized = enforce_types(payload, schema)
    if fallback:
        normalized = fill_missing_fields(normalized, fallback)
    return normalized
