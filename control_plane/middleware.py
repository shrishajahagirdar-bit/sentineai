from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Callable

from fastapi import Request, Response
from observability.context import set_correlation_id, set_tenant_id
from observability.logging import configure_json_logger
from observability.metrics import SERVICE_HEALTH


def configure_request_logger() -> logging.Logger:
    log_path = Path(__file__).resolve().parents[1] / "logs" / "control_plane.log"
    return configure_json_logger("sentinelai.control_plane", log_path)


async def request_logging_middleware(request: Request, call_next: Callable[..., Response]) -> Response:
    logger = configure_request_logger()
    correlation_id = set_correlation_id(request.headers.get("x-correlation-id"))
    set_tenant_id(request.headers.get("x-tenant-id"))
    started = time.perf_counter()
    SERVICE_HEALTH.labels(service="control-plane-api").set(1)
    response = await call_next(request)
    duration_ms = round((time.perf_counter() - started) * 1000, 2)
    response.headers["x-correlation-id"] = correlation_id
    logger.info(
        "request completed",
        extra={
            "payload": {
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "tenant_id": getattr(request.state, "tenant_id", None),
                "user_id": getattr(request.state, "user_id", None),
                "duration_ms": duration_ms,
                "correlation_id": correlation_id,
            }
        },
    )
    return response
