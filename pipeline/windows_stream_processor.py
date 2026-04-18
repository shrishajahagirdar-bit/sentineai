#!/usr/bin/env python3
"""
Windows Telemetry Stream Processor
===================================

Consumes raw Windows telemetry from 'windows-telemetry' topic,
enriches events with ML scoring, risk analysis, and behavioral insights,
then publishes enriched events to 'scored-events' topic.

This service transforms raw OS logs into SOC-ready intelligence.
"""

from __future__ import annotations

import asyncio
import json
import logging
import signal
import sys
import time
from typing import Any, Dict, List, Optional

from pipeline.stream_processor import StreamProcessor
from sentinel_config import CONFIG

try:
    from confluent_kafka import Consumer as ConfluentConsumer, Producer as ConfluentProducer
except ImportError:
    ConfluentConsumer = None
    ConfluentProducer = None

logger = logging.getLogger(__name__)


class WindowsTelemetryStreamProcessor:
    """
    Stream processor for Windows telemetry events.

    Consumes: windows-telemetry
    Produces: scored-events
    """

    def __init__(self):
        self.consumer_topic = "windows-telemetry"
        self.producer_topic = CONFIG.kafka_scored_topic  # "scored-events"
        self.group_id = "windows-stream-processor"

        self.consumer: Optional[ConfluentConsumer] = None
        self.producer: Optional[ConfluentProducer] = None
        self.stream_processor = StreamProcessor()

        self.running = False
        self.stats = {
            "events_consumed": 0,
            "events_processed": 0,
            "events_published": 0,
            "errors": 0
        }

    def initialize(self) -> bool:
        """Initialize Kafka consumer and producer."""
        try:
            # Initialize consumer
            if ConfluentConsumer is None:
                logger.error("Confluent Kafka not available")
                return False

            self.consumer = ConfluentConsumer({
                "bootstrap.servers": ",".join(CONFIG.kafka_bootstrap_servers),
                "group.id": self.group_id,
                "auto.offset.reset": "latest",
                "enable.auto.commit": True,
            })
            self.consumer.subscribe([self.consumer_topic])

            # Initialize producer
            self.producer = ConfluentProducer({
                "bootstrap.servers": ",".join(CONFIG.kafka_bootstrap_servers),
            })

            logger.info(f"Initialized stream processor: {self.consumer_topic} → {self.producer_topic}")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize stream processor: {e}")
            return False

    def _normalize_windows_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Windows telemetry event to canonical format."""
        # Map Windows Event IDs to event types
        event_id = raw_event.get("event_id", 0)
        event_type_map = {
            4624: "login_success",
            4625: "login_failure",
            4634: "logout",
            4688: "process_creation",
            4689: "process_termination",
        }

        # Map MITRE ATT&CK techniques
        mitre_technique_map = {
            4624: "T1078",  # Valid Accounts
            4625: "T1110",  # Brute Force
            4688: "T1059",  # Command and Scripting Interpreter
        }

        # Map attack stages
        attack_stage_map = {
            4624: "initial_access",
            4625: "initial_access",
            4688: "execution",
        }

        normalized = {
            "timestamp": raw_event.get("timestamp"),
            "host": raw_event.get("host", "unknown"),
            "user": raw_event.get("user", "unknown"),
            "event_type": event_type_map.get(event_id, "unknown"),
            "source": raw_event.get("source", "windows_security"),
            "event_id": event_id,
            "severity": raw_event.get("severity", "low"),
            "tenant_id": raw_event.get("tenant_id", "default"),
            "process_name": raw_event.get("process_name", ""),
            "command_line": raw_event.get("command_line", ""),
            "ip_address": raw_event.get("ip_address", ""),
            "mitre_technique": mitre_technique_map.get(event_id, "T0000"),
            "attack_stage": attack_stage_map.get(event_id, "unknown"),
            "raw_event": raw_event
        }

        return normalized

    def _publish_enriched_event(self, enriched_result: Dict[str, Any]) -> bool:
        """Publish enriched event to scored-events topic."""
        if self.producer is None:
            return False

        try:
            # Extract the enriched event
            event = enriched_result.get("event", {})

            # Add processing metadata
            event["processed_at"] = time.time()
            event["processor_version"] = "1.0.0"

            # Publish to Kafka
            self.producer.produce(
                self.producer_topic,
                key=event.get("tenant_id", "default"),
                value=json.dumps(event, default=str)
            )
            self.producer.flush()

            self.stats["events_published"] += 1
            return True

        except Exception as e:
            logger.error(f"Failed to publish enriched event: {e}")
            self.stats["errors"] += 1
            return False

    def process_batch(self, messages: List[Any]) -> None:
        """Process a batch of raw Windows telemetry events."""
        for message in messages:
            try:
                self.stats["events_consumed"] += 1

                # Parse raw message
                if hasattr(message, 'value'):
                    raw_event = json.loads(message.value().decode('utf-8'))
                else:
                    raw_event = message

                # Normalize to canonical format
                normalized_event = self._normalize_windows_event(raw_event)

                # Process through stream processor
                enriched_result = self.stream_processor.process_event(normalized_event, persist=True)

                # Publish enriched event
                if self._publish_enriched_event(enriched_result):
                    self.stats["events_processed"] += 1

            except Exception as e:
                logger.error(f"Error processing event: {e}")
                self.stats["errors"] += 1

    def run(self) -> None:
        """Run the stream processor continuously."""
        if not self.initialize():
            return

        self.running = True
        logger.info("Windows Telemetry Stream Processor started")

        try:
            while self.running:
                # Poll for messages
                messages = self.consumer.poll(timeout=1.0)

                if messages:
                    # Process batch
                    if hasattr(messages, '__iter__') and not isinstance(messages, (str, bytes)):
                        self.process_batch(messages)
                    else:
                        self.process_batch([messages])

                # Log stats periodically
                if self.stats["events_consumed"] % 100 == 0 and self.stats["events_consumed"] > 0:
                    logger.info(f"Stream processor stats: {self.stats}")

        except KeyboardInterrupt:
            logger.info("Stream processor interrupted")
        except Exception as e:
            logger.error(f"Stream processor error: {e}")
        finally:
            self.shutdown()

    def shutdown(self) -> None:
        """Shutdown the stream processor."""
        self.running = False

        if self.consumer:
            self.consumer.close()

        if self.producer:
            self.producer.flush()

        logger.info(f"Stream processor shutdown. Final stats: {self.stats}")


def main():
    """Main entry point."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | WindowsStreamProcessor | %(levelname)s | %(message)s"
    )

    processor = WindowsTelemetryStreamProcessor()

    # Handle shutdown signals
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        processor.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Run processor
    processor.run()


if __name__ == "__main__":
    main()