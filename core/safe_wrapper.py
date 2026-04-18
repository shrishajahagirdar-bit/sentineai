from __future__ import annotations

import json
import logging
from functools import wraps
from pathlib import Path
from typing import Any, Callable

from observability.context import get_correlation_id, get_tenant_id
from observability.logging import JsonLogFormatter


LOG_PATH = Path(__file__).resolve().parents[1] / "logs" / "system_health.log"
LOGGER_NAME = "sentinelai.system_health"


def _get_logger() -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    if logger.handlers:
        return logger

    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    logger.setLevel(logging.INFO)
    handler = logging.FileHandler(LOG_PATH, encoding="utf-8")
    handler.setFormatter(JsonLogFormatter())
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def log_health_event(
    level: str,
    event_type: str,
    message: str,
    context: dict[str, Any] | None = None,
    exc_info: bool = False,
) -> None:
    payload = {
        "level": level.upper(),
        "event_type": event_type,
        "message": message,
        "context": context or {},
        "correlation_id": get_correlation_id(),
        "tenant_id": get_tenant_id(),
    }
    logger = _get_logger()
    log_method = getattr(logger, level.lower(), logger.info)
    log_method(message, extra={"payload": payload}, exc_info=exc_info)


def safe_execution(
    func: Callable[..., Any] | None = None,
    *,
    default_factory: Callable[[], Any] | None = None,
    operation: str | None = None,
) -> Callable[..., Any]:
    def decorator(inner: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(inner)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return inner(*args, **kwargs)
            except Exception as exc:
                log_health_event(
                    "error",
                    operation or inner.__name__,
                    str(exc),
                    context={
                        "args_count": len(args),
                        "kwargs": list(kwargs.keys()),
                    },
                    exc_info=True,
                )
                if default_factory is not None:
                    return default_factory()
                return {
                    "status": "safe_fallback",
                    "message": "data unavailable",
                    "risk_score": 0,
                }

        return wrapper

    if func is not None:
        return decorator(func)
    return decorator
