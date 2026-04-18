from __future__ import annotations

# Windows Telemetry Streaming Components
from .windows_log_collector import (
    WindowsLogCollector,
    WindowsTelemetryEvent,
    start_windows_collector,
    stop_windows_collector,
)
from .transport.http_fallback import HTTPFallbackTransport
from .schema_validator import (
    WindowsTelemetrySchemaValidator,
    validate_windows_event,
    validate_windows_events,
)

__all__ = [
    "main",
    # Windows Telemetry
    "WindowsLogCollector",
    "WindowsTelemetryEvent",
    "start_windows_collector",
    "stop_windows_collector",
    "HTTPFallbackTransport",
    "WindowsTelemetrySchemaValidator",
    "validate_windows_event",
    "validate_windows_events",
]
