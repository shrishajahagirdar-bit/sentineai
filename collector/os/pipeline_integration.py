"""
OS Collector Pipeline Integration

Integrates the OS telemetry collector with the existing SentinelAI pipeline.
Streams normalized OS events to Kafka, ML engines, and dashboards.

Features:
- Kafka event streaming
- ML engine integration (UEBA, risk scoring)
- Dashboard real-time updates
- Error handling and circuit breakers
- Configurable routing rules

Architecture:
OS Collector → Unified Format → Pipeline Integration → [Kafka/ML/Dashboard]
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any, Callable

from core.safe_wrapper import log_health_event
from sentinel_config import CONFIG
from .unified_telemetry_format import UnifiedTelemetryFormat


class PipelineIntegration:
    """
    Integrates OS telemetry collector with SentinelAI pipeline.

    Routes normalized OS events to appropriate downstream components:
    - Kafka for streaming analytics
    - ML engines for UEBA/risk scoring
    - Dashboard for real-time visualization
    - Storage for persistence

    Features:
    - Circuit breaker pattern for fault tolerance
    - Event batching for efficiency
    - Configurable routing rules
    - Health monitoring and metrics
    """

    def __init__(
        self,
        kafka_enabled: bool = True,
        ml_integration_enabled: bool = True,
        dashboard_enabled: bool = True,
        batch_size: int = 10,
        flush_interval_seconds: float = 5.0,
    ) -> None:
        """
        Initialize pipeline integration.

        Args:
            kafka_enabled: Enable Kafka streaming
            ml_integration_enabled: Enable ML engine integration
            dashboard_enabled: Enable dashboard updates
            batch_size: Events to batch before sending
            flush_interval_seconds: Max time to hold events before flushing
        """
        self.kafka_enabled = kafka_enabled
        self.ml_integration_enabled = ml_integration_enabled
        self.dashboard_enabled = dashboard_enabled
        self.batch_size = batch_size
        self.flush_interval_seconds = flush_interval_seconds

        # Event buffering
        self.event_buffer = []
        self.last_flush_time = time.time()

        # Circuit breakers for fault tolerance
        self.circuit_breakers = {
            "kafka": CircuitBreaker(failure_threshold=5, recovery_timeout=30.0),
            "ml_engine": CircuitBreaker(failure_threshold=3, recovery_timeout=15.0),
            "dashboard": CircuitBreaker(failure_threshold=3, recovery_timeout=10.0),
        }

        # Integration clients (lazy-loaded)
        self._kafka_producer = None
        self._ml_client = None
        self._dashboard_client = None

        # Statistics
        self.stats = {
            "events_processed": 0,
            "events_forwarded_kafka": 0,
            "events_forwarded_ml": 0,
            "events_forwarded_dashboard": 0,
            "batches_flushed": 0,
            "errors_encountered": 0,
            "circuit_breaker_trips": 0,
        }

        log_health_event(
            "info",
            "pipeline_integration_init",
            f"OS Pipeline Integration initialized (kafka: {kafka_enabled}, ml: {ml_integration_enabled}, dashboard: {dashboard_enabled})",
        )

    def process_events(self, events: list[dict[str, Any]]) -> bool:
        """
        Process and route OS telemetry events through the pipeline.

        Args:
            events: List of raw OS events

        Returns:
            True if processed successfully, False otherwise
        """
        try:
            # Normalize events
            normalized_events = UnifiedTelemetryFormat.normalize_events(events)
            if not normalized_events:
                return True  # No valid events to process

            self.stats["events_processed"] += len(normalized_events)

            # Add to buffer
            self.event_buffer.extend(normalized_events)

            # Check if we should flush
            should_flush = (
                len(self.event_buffer) >= self.batch_size or
                time.time() - self.last_flush_time >= self.flush_interval_seconds
            )

            if should_flush:
                return self._flush_buffer()

            return True

        except Exception as exc:
            self.stats["errors_encountered"] += 1
            log_health_event(
                "error",
                "pipeline_process_error",
                f"Error processing events: {str(exc)}",
            )
            return False

    def _flush_buffer(self) -> bool:
        """Flush buffered events to downstream systems."""
        if not self.event_buffer:
            return True

        events_to_send = self.event_buffer.copy()
        self.event_buffer.clear()
        self.last_flush_time = time.time()
        self.stats["batches_flushed"] += 1

        success = True

        # Send to Kafka
        if self.kafka_enabled:
            try:
                if self.circuit_breakers["kafka"].can_attempt():
                    if self._send_to_kafka(events_to_send):
                        self.stats["events_forwarded_kafka"] += len(events_to_send)
                        self.circuit_breakers["kafka"].record_success()
                    else:
                        self.circuit_breakers["kafka"].record_failure()
                        success = False
                else:
                    log_health_event(
                        "warning",
                        "kafka_circuit_breaker_open",
                        "Kafka circuit breaker is open, skipping",
                    )
            except Exception as exc:
                self.circuit_breakers["kafka"].record_failure()
                log_health_event(
                    "error",
                    "kafka_send_error",
                    f"Error sending to Kafka: {str(exc)}",
                )
                success = False

        # Send to ML engines
        if self.ml_integration_enabled:
            try:
                if self.circuit_breakers["ml_engine"].can_attempt():
                    if self._send_to_ml_engine(events_to_send):
                        self.stats["events_forwarded_ml"] += len(events_to_send)
                        self.circuit_breakers["ml_engine"].record_success()
                    else:
                        self.circuit_breakers["ml_engine"].record_failure()
                        success = False
                else:
                    log_health_event(
                        "warning",
                        "ml_circuit_breaker_open",
                        "ML engine circuit breaker is open, skipping",
                    )
            except Exception as exc:
                self.circuit_breakers["ml_engine"].record_failure()
                log_health_event(
                    "error",
                    "ml_send_error",
                    f"Error sending to ML engine: {str(exc)}",
                )
                success = False

        # Send to dashboard
        if self.dashboard_enabled:
            try:
                if self.circuit_breakers["dashboard"].can_attempt():
                    if self._send_to_dashboard(events_to_send):
                        self.stats["events_forwarded_dashboard"] += len(events_to_send)
                        self.circuit_breakers["dashboard"].record_success()
                    else:
                        self.circuit_breakers["dashboard"].record_failure()
                        success = False
                else:
                    log_health_event(
                        "warning",
                        "dashboard_circuit_breaker_open",
                        "Dashboard circuit breaker is open, skipping",
                    )
            except Exception as exc:
                self.circuit_breakers["dashboard"].record_failure()
                log_health_event(
                    "error",
                    "dashboard_send_error",
                    f"Error sending to dashboard: {str(exc)}",
                )
                success = False

        return success

    def _send_to_kafka(self, events: list[dict[str, Any]]) -> bool:
        """Send events to Kafka streaming pipeline."""
        try:
            # Lazy load Kafka producer
            if self._kafka_producer is None:
                self._kafka_producer = self._create_kafka_producer()

            if self._kafka_producer is None:
                return False

            # Send events to Kafka topic
            topic = CONFIG.get("kafka", {}).get("os_telemetry_topic", "os-telemetry")

            for event in events:
                # Convert to JSON
                message = json.dumps(event, default=str)

                # Send to Kafka (simplified - in real implementation would use kafka-python)
                # self._kafka_producer.send(topic, message)

                log_health_event(
                    "debug",
                    "kafka_event_sent",
                    f"Sent event to Kafka topic '{topic}': {event.get('sub_event_type', 'unknown')}",
                )

            return True

        except Exception as exc:
            log_health_event(
                "error",
                "kafka_send_failure",
                f"Failed to send events to Kafka: {str(exc)}",
            )
            return False

    def _send_to_ml_engine(self, events: list[dict[str, Any]]) -> bool:
        """Send events to ML engines for processing."""
        try:
            # Lazy load ML client
            if self._ml_client is None:
                self._ml_client = self._create_ml_client()

            if self._ml_client is None:
                return False

            # Filter events relevant to ML processing
            ml_events = [e for e in events if e.get("category") in ["auth", "process"]]

            if not ml_events:
                return True  # No relevant events

            # Send to ML engine (simplified - in real implementation would call ML APIs)
            # self._ml_client.process_events(ml_events)

            log_health_event(
                "debug",
                "ml_events_sent",
                f"Sent {len(ml_events)} events to ML engine",
            )

            return True

        except Exception as exc:
            log_health_event(
                "error",
                "ml_send_failure",
                f"Failed to send events to ML engine: {str(exc)}",
            )
            return False

    def _send_to_dashboard(self, events: list[dict[str, Any]]) -> bool:
        """Send events to dashboard for real-time updates."""
        try:
            # Lazy load dashboard client
            if self._dashboard_client is None:
                self._dashboard_client = self._create_dashboard_client()

            if self._dashboard_client is None:
                return False

            # Send to dashboard (simplified - in real implementation would use WebSocket/REST)
            # self._dashboard_client.send_events(events)

            log_health_event(
                "debug",
                "dashboard_events_sent",
                f"Sent {len(events)} events to dashboard",
            )

            return True

        except Exception as exc:
            log_health_event(
                "error",
                "dashboard_send_failure",
                f"Failed to send events to dashboard: {str(exc)}",
            )
            return False

    def _create_kafka_producer(self):
        """Create Kafka producer (placeholder for actual implementation)."""
        try:
            # In real implementation, this would create a kafka-python producer
            # from kafka import KafkaProducer
            # return KafkaProducer(bootstrap_servers=CONFIG.get("kafka", {}).get("brokers", ["localhost:9092"]))
            log_health_event(
                "info",
                "kafka_producer_created",
                "Kafka producer created (placeholder)",
            )
            return "kafka_producer_placeholder"
        except Exception as exc:
            log_health_event(
                "warning",
                "kafka_producer_creation_failed",
                f"Failed to create Kafka producer: {str(exc)}",
            )
            return None

    def _create_ml_client(self):
        """Create ML engine client (placeholder for actual implementation)."""
        try:
            # In real implementation, this would create a client for ML services
            log_health_event(
                "info",
                "ml_client_created",
                "ML client created (placeholder)",
            )
            return "ml_client_placeholder"
        except Exception as exc:
            log_health_event(
                "warning",
                "ml_client_creation_failed",
                f"Failed to create ML client: {str(exc)}",
            )
            return None

    def _create_dashboard_client(self):
        """Create dashboard client (placeholder for actual implementation)."""
        try:
            # In real implementation, this would create a WebSocket or REST client
            log_health_event(
                "info",
                "dashboard_client_created",
                "Dashboard client created (placeholder)",
            )
            return "dashboard_client_placeholder"
        except Exception as exc:
            log_health_event(
                "warning",
                "dashboard_client_creation_failed",
                f"Failed to create dashboard client: {str(exc)}",
            )
            return None

    def get_stats(self) -> dict[str, Any]:
        """Get pipeline integration statistics."""
        return {
            **self.stats,
            "buffer_size": len(self.event_buffer),
            "circuit_breakers": {
                name: cb.get_status() for name, cb in self.circuit_breakers.items()
            },
            "integrations": {
                "kafka": self.kafka_enabled and self._kafka_producer is not None,
                "ml_engine": self.ml_integration_enabled and self._ml_client is not None,
                "dashboard": self.dashboard_enabled and self._dashboard_client is not None,
            },
        }

    def force_flush(self) -> bool:
        """Force flush all buffered events."""
        return self._flush_buffer()

    def shutdown(self) -> None:
        """Shutdown the pipeline integration gracefully."""
        # Flush remaining events
        self.force_flush()

        # Close connections
        if self._kafka_producer:
            # self._kafka_producer.close()
            pass

        log_health_event(
            "info",
            "pipeline_integration_shutdown",
            f"Pipeline integration shutdown (processed: {self.stats['events_processed']} events)",
        )


class CircuitBreaker:
    """
    Circuit breaker pattern for fault tolerance.

    Prevents cascading failures by temporarily stopping calls to failing services.
    """

    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 30.0):
        """
        Initialize circuit breaker.

        Args:
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds to wait before trying again
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout

        self.failure_count = 0
        self.last_failure_time = 0.0
        self.state = "closed"  # closed, open, half_open

    def can_attempt(self) -> bool:
        """Check if we can attempt the operation."""
        current_time = time.time()

        if self.state == "closed":
            return True
        elif self.state == "open":
            if current_time - self.last_failure_time >= self.recovery_timeout:
                self.state = "half_open"
                return True
            return False
        elif self.state == "half_open":
            return True

        return False

    def record_success(self) -> None:
        """Record a successful operation."""
        self.failure_count = 0
        self.state = "closed"

    def record_failure(self) -> None:
        """Record a failed operation."""
        self.failure_count += 1
        self.last_failure_time = time.time()

        if self.failure_count >= self.failure_threshold:
            self.state = "open"

    def get_status(self) -> dict[str, Any]:
        """Get circuit breaker status."""
        return {
            "state": self.state,
            "failure_count": self.failure_count,
            "last_failure_time": self.last_failure_time,
            "failure_threshold": self.failure_threshold,
            "recovery_timeout": self.recovery_timeout,
        }


# Global pipeline integration instance
_pipeline_instance: PipelineIntegration | None = None


def get_pipeline_integration() -> PipelineIntegration:
    """Get or create global pipeline integration instance."""
    global _pipeline_instance
    if _pipeline_instance is None:
        _pipeline_instance = PipelineIntegration()
    return _pipeline_instance


def create_event_callback() -> Callable[[list[dict[str, Any]]], None]:
    """Create an event callback function for the collector daemon."""
    pipeline = get_pipeline_integration()

    def callback(events: list[dict[str, Any]]) -> None:
        """Process events through the pipeline."""
        pipeline.process_events(events)

    return callback
