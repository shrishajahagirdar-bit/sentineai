"""
OS Telemetry Collector Module

Production-grade OS telemetry collection for SentinelAI EDR.
Reads real Windows Event Logs and process telemetry.

Modules:
- windows_event_collector: Windows Event Log reader
- process_monitor: Real-time process monitoring via psutil
- collector_daemon: Background polling engine
- unified_telemetry_format: Event normalization
- pipeline_integration: Integration with SentinelAI pipeline

Safety Features:
- User-mode only (no kernel drivers)
- Graceful fallback for unavailable logs
- Memory-safe operation
- Error handling and recovery
"""

from .windows_event_collector import WindowsEventCollector
from .process_monitor import ProcessMonitor
from .collector_daemon import CollectorDaemon, get_global_daemon, start_global_daemon, stop_global_daemon
from .unified_telemetry_format import UnifiedTelemetryFormat
from .pipeline_integration import PipelineIntegration, get_pipeline_integration, create_event_callback

__all__ = [
    "WindowsEventCollector",
    "ProcessMonitor",
    "CollectorDaemon",
    "UnifiedTelemetryFormat",
    "PipelineIntegration",
    "get_global_daemon",
    "start_global_daemon",
    "stop_global_daemon",
    "get_pipeline_integration",
    "create_event_callback",
]
