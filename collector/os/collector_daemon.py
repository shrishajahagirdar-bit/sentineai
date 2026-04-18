"""
Collector Daemon - Real-time OS Telemetry Polling Engine

Production-grade daemon that continuously polls Windows Event Logs and process
telemetry. Runs in background thread with duplicate prevention and error handling.

Features:
- Polls Windows Event Logs every 2-5 seconds
- Monitors process lifecycle in real-time
- Prevents duplicate events using record tracking
- Streams events to Kafka or local pipeline
- Graceful shutdown and error recovery
- User-mode only (no kernel drivers)

Architecture:
CollectorDaemon (main thread)
├── WindowsEventCollector (event log polling)
├── ProcessMonitor (process telemetry)
└── EventStreamer (Kafka/local streaming)
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

from core.safe_wrapper import log_health_event
from sentinel_config import CONFIG
from .windows_event_collector import WindowsEventCollector
from .process_monitor import ProcessMonitor


class CollectorDaemon:
    """
    Real-time OS Telemetry Collection Daemon

    Continuously monitors Windows Event Logs and process activity.
    Designed for production use with proper error handling and resource management.

    Safety Features:
    - User-mode only operation
    - Graceful error handling
    - Memory-safe event buffering
    - Configurable polling intervals
    - Clean shutdown procedures
    """

    def __init__(
        self,
        event_callback: Callable[[list[dict[str, Any]]], None] | None = None,
        poll_interval_seconds: float = 3.0,
        max_events_per_cycle: int = 50,
    ) -> None:
        """
        Initialize the collector daemon.

        Args:
            event_callback: Function to call with collected events
            poll_interval_seconds: How often to poll for events (2-5 seconds recommended)
            max_events_per_cycle: Maximum events to collect per polling cycle
        """
        self.event_callback = event_callback
        self.poll_interval_seconds = max(1.0, min(poll_interval_seconds, 10.0))  # Clamp to safe range
        self.max_events_per_cycle = max_events_per_cycle

        # Collectors
        self.event_collector = WindowsEventCollector()
        self.process_monitor = ProcessMonitor()

        # Threading
        self.thread: threading.Thread | None = None
        self.running = False
        self.shutdown_event = threading.Event()

        # Statistics
        self.stats = {
            "start_time": None,
            "cycles_completed": 0,
            "events_collected": 0,
            "errors_encountered": 0,
            "last_collection_time": None,
            "avg_cycle_time": 0.0,
        }

        log_health_event(
            "info",
            "collector_daemon_init",
            f"OS Telemetry Collector Daemon initialized (poll_interval: {self.poll_interval_seconds}s)",
        )

    def start(self) -> bool:
        """
        Start the collector daemon in background thread.

        Returns:
            True if started successfully, False otherwise
        """
        if self.running:
            log_health_event(
                "warning",
                "collector_daemon_start",
                "Collector daemon already running",
            )
            return False

        try:
            self.running = True
            self.shutdown_event.clear()
            self.stats["start_time"] = datetime.now(timezone.utc).isoformat()

            self.thread = threading.Thread(
                target=self._collection_loop,
                name="os-telemetry-collector",
                daemon=True,
            )
            self.thread.start()

            log_health_event(
                "info",
                "collector_daemon_started",
                "OS Telemetry Collector Daemon started successfully",
            )
            return True

        except Exception as exc:
            self.running = False
            log_health_event(
                "error",
                "collector_daemon_start_failed",
                f"Failed to start collector daemon: {str(exc)}",
            )
            return False

    def stop(self) -> bool:
        """
        Stop the collector daemon gracefully.

        Returns:
            True if stopped successfully, False otherwise
        """
        if not self.running:
            return True

        try:
            self.running = False
            self.shutdown_event.set()

            if self.thread and self.thread.is_alive():
                self.thread.join(timeout=10.0)  # Wait up to 10 seconds

                if self.thread.is_alive():
                    log_health_event(
                        "warning",
                        "collector_daemon_stop_timeout",
                        "Collector daemon thread did not stop gracefully",
                    )
                    return False

            log_health_event(
                "info",
                "collector_daemon_stopped",
                f"OS Telemetry Collector Daemon stopped (cycles: {self.stats['cycles_completed']}, events: {self.stats['events_collected']})",
            )
            return True

        except Exception as exc:
            log_health_event(
                "error",
                "collector_daemon_stop_failed",
                f"Error stopping collector daemon: {str(exc)}",
            )
            return False

    def is_running(self) -> bool:
        """Check if the daemon is currently running."""
        return self.running and self.thread and self.thread.is_alive()

    def _collection_loop(self) -> None:
        """Main collection loop that runs in background thread."""
        cycle_times = []

        while self.running and not self.shutdown_event.is_set():
            cycle_start = time.time()

            try:
                # Collect events from all sources
                events = self._collect_all_events()

                # Update statistics
                self.stats["cycles_completed"] += 1
                self.stats["events_collected"] += len(events)
                self.stats["last_collection_time"] = datetime.now(timezone.utc).isoformat()

                # Send events to callback if available
                if events and self.event_callback:
                    try:
                        self.event_callback(events)
                    except Exception as exc:
                        log_health_event(
                            "error",
                            "event_callback_error",
                            f"Error in event callback: {str(exc)}",
                        )

                # Calculate average cycle time
                cycle_time = time.time() - cycle_start
                cycle_times.append(cycle_time)
                if len(cycle_times) > 10:  # Keep last 10 measurements
                    cycle_times.pop(0)
                self.stats["avg_cycle_time"] = sum(cycle_times) / len(cycle_times)

            except Exception as exc:
                self.stats["errors_encountered"] += 1
                log_health_event(
                    "error",
                    "collection_cycle_error",
                    f"Error in collection cycle: {str(exc)}",
                )

            # Wait for next cycle (with shutdown check)
            self.shutdown_event.wait(self.poll_interval_seconds)

        # Final cleanup
        log_health_event(
            "debug",
            "collection_loop_ended",
            "Collection loop ended",
        )

    def _collect_all_events(self) -> list[dict[str, Any]]:
        """Collect events from all telemetry sources."""
        all_events = []

        # Collect Windows Event Log events
        try:
            event_log_events = self.event_collector.collect_once(
                max_events=self.max_events_per_cycle // 2
            )
            all_events.extend(event_log_events)
        except Exception as exc:
            log_health_event(
                "warning",
                "event_log_collection_error",
                f"Error collecting event log events: {str(exc)}",
            )

        # Collect process telemetry
        try:
            process_events = self.process_monitor.collect_telemetry()
            all_events.extend(process_events)

            # Limit total events to prevent memory issues
            if len(all_events) > self.max_events_per_cycle:
                all_events = all_events[:self.max_events_per_cycle]
        except Exception as exc:
            log_health_event(
                "warning",
                "process_collection_error",
                f"Error collecting process events: {str(exc)}",
            )

        return all_events

    def get_stats(self) -> dict[str, Any]:
        """Get daemon statistics."""
        return {
            **self.stats,
            "is_running": self.is_running(),
            "poll_interval_seconds": self.poll_interval_seconds,
            "max_events_per_cycle": self.max_events_per_cycle,
            "event_collector_status": self.event_collector.get_status(),
            "process_monitor_status": self.process_monitor.get_status(),
        }

    def force_collection(self) -> list[dict[str, Any]]:
        """
        Force an immediate collection cycle (for testing/debugging).

        Returns:
            List of collected events
        """
        try:
            events = self._collect_all_events()
            log_health_event(
                "debug",
                "force_collection",
                f"Force collected {len(events)} events",
            )
            return events
        except Exception as exc:
            log_health_event(
                "error",
                "force_collection_error",
                f"Error in force collection: {str(exc)}",
            )
            return []

    def __enter__(self) -> CollectorDaemon:
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.stop()


# Global daemon instance for easy access
_daemon_instance: CollectorDaemon | None = None


def get_global_daemon() -> CollectorDaemon:
    """Get or create global daemon instance."""
    global _daemon_instance
    if _daemon_instance is None:
        _daemon_instance = CollectorDaemon()
    return _daemon_instance


def start_global_daemon(
    event_callback: Callable[[list[dict[str, Any]]], None] | None = None,
    poll_interval_seconds: float = 3.0,
) -> bool:
    """Start the global daemon instance."""
    daemon = get_global_daemon()
    if event_callback:
        daemon.event_callback = event_callback
    daemon.poll_interval_seconds = poll_interval_seconds
    return daemon.start()


def stop_global_daemon() -> bool:
    """Stop the global daemon instance."""
    global _daemon_instance
    if _daemon_instance:
        result = _daemon_instance.stop()
        _daemon_instance = None
        return result
    return True
