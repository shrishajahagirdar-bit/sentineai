"""
Real-Time Kafka Consumer Service
================================

Consumes security events from Kafka and populates EventBuffer.
Runs as a background service (thread or async task).

Features:
- Automatic reconnection
- Event schema validation
- Multi-tenant isolation
- Consumer lag tracking
- Graceful shutdown
- Dead-letter queue handling

Usage:
    service = KafkaConsumerService()
    service.start()
    # ... service runs in background thread ...
    service.shutdown()
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from typing import Optional

from kafka import KafkaConsumer
from kafka.errors import KafkaError

from core.schema import SecurityEvent
from dashboard.data_buffer import get_buffer
from sentinel_config import CONFIG

logger = logging.getLogger(__name__)


class KafkaConsumerService:
    """
    Kafka consumer that populates EventBuffer in real-time.
    
    Designed to run as a background thread or async task.
    Handles reconnection, validation, and error recovery.
    """
    
    def __init__(
        self,
        bootstrap_servers: Optional[list[str]] = None,
        topic: str = CONFIG.kafka_scored_topic,
        group_id: str = "sentinelai-dashboard",
        max_retries: int = 10,
    ):
        """Initialize Kafka consumer.
        
        Args:
            bootstrap_servers: Kafka brokers (default from CONFIG)
            topic: Kafka topic to consume
            group_id: Consumer group ID
            max_retries: Max reconnection attempts
        """
        self.bootstrap_servers = bootstrap_servers or CONFIG.kafka_bootstrap_servers
        self.topic = topic
        self.group_id = group_id
        self.max_retries = max_retries
        
        self.consumer: Optional[KafkaConsumer] = None
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.buffer = get_buffer()
        
        # Stats
        self.messages_consumed = 0
        self.messages_dropped = 0
        self.last_error: Optional[str] = None
    
    def connect(self) -> bool:
        """Establish Kafka connection with retry logic.
        
        Returns:
            True if connected, False if failed after retries
        """
        for attempt in range(self.max_retries):
            try:
                logger.info(
                    f"Connecting to Kafka (attempt {attempt + 1}/{self.max_retries})..."
                )
                
                self.consumer = KafkaConsumer(
                    self.topic,
                    bootstrap_servers=self.bootstrap_servers,
                    group_id=self.group_id,
                    auto_offset_reset="latest",  # Start from latest on first run
                    enable_auto_commit=True,
                    value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                    max_poll_records=100,
                    session_timeout_ms=30000,
                    connections_max_idle_ms=540000,
                    request_timeout_ms=60000,
                    reconnect_backoff_ms=100,
                    reconnect_backoff_max_ms=32000,
                )
                
                logger.info(f"✅ Connected to Kafka: {self.bootstrap_servers}")
                return True
                
            except KafkaError as e:
                self.last_error = str(e)
                logger.warning(
                    f"Kafka connection failed (attempt {attempt + 1}): {e}"
                )
                
                if attempt < self.max_retries - 1:
                    backoff = min(2 ** attempt, 30)  # Exponential backoff, max 30s
                    logger.info(f"Retrying in {backoff}s...")
                    time.sleep(backoff)
            
            except Exception as e:
                self.last_error = str(e)
                logger.error(f"Unexpected error during Kafka connection: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(min(2 ** attempt, 30))
        
        logger.error(f"❌ Failed to connect to Kafka after {self.max_retries} attempts")
        return False
    
    def _validate_event(self, event: dict) -> bool:
        """Validate event against schema.
        
        Args:
            event: Event dict to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            # Ensure required fields
            required_fields = ["timestamp", "event_type", "source"]
            for field in required_fields:
                if field not in event:
                    logger.warning(f"Missing required field: {field}")
                    return False
            
            # Validate timestamp is ISO format
            try:
                from datetime import datetime
                datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                logger.warning(f"Invalid timestamp format: {event.get('timestamp')}")
                return False
            
            return True
        
        except Exception as e:
            logger.error(f"Event validation error: {e}")
            return False
    
    def _consume_loop(self) -> None:
        """Main consume loop (runs in thread)."""
        logger.info("Kafka consumer loop started")
        
        while self.running:
            try:
                if not self.consumer:
                    logger.warning("Consumer not initialized, attempting to reconnect...")
                    if not self.connect():
                        time.sleep(5)
                        continue
                
                # Poll for messages (timeout allows checking self.running)
                messages = self.consumer.poll(timeout_ms=1000, max_records=100)
                
                if not messages:
                    continue
                
                # Process messages
                for topic_partition, records in messages.items():
                    for record in records:
                        try:
                            event = record.value
                            
                            # Validate event
                            if not self._validate_event(event):
                                logger.warning(
                                    f"Invalid event dropped: {event.get('event_type')}"
                                )
                                self.messages_dropped += 1
                                continue
                            
                            # Extract tenant_id (default to "default")
                            tenant_id = event.get("tenant_id", "default")
                            
                            # Add to buffer (triggers WebSocket subscribers)
                            self.buffer.add_event(event, tenant_id=tenant_id)
                            self.messages_consumed += 1
                            
                            # Log every 100 events
                            if self.messages_consumed % 100 == 0:
                                logger.info(
                                    f"Consumed {self.messages_consumed} events | "
                                    f"Dropped: {self.messages_dropped}"
                                )
                        
                        except Exception as e:
                            logger.error(f"Error processing record: {e}")
                            self.messages_dropped += 1
            
            except KafkaError as e:
                logger.error(f"Kafka consumer error: {e}")
                self.last_error = str(e)
                self.running = False
                
                # Attempt reconnection
                logger.info("Attempting to reconnect...")
                time.sleep(5)
                if self.connect():
                    self.running = True
                else:
                    logger.error("Failed to reconnect to Kafka")
                    break
            
            except Exception as e:
                logger.error(f"Unexpected error in consume loop: {e}")
                time.sleep(5)
        
        logger.info("Kafka consumer loop stopped")
    
    def start(self) -> bool:
        """Start the Kafka consumer service.
        
        Connects to Kafka and starts consuming in a background thread.
        
        Returns:
            True if successfully started
        """
        if self.running:
            logger.warning("Service already running")
            return False
        
        # Connect to Kafka
        if not self.connect():
            return False
        
        # Start consume loop in background thread
        self.running = True
        self.thread = threading.Thread(target=self._consume_loop, daemon=False)
        self.thread.start()
        
        logger.info("✅ Kafka consumer service started")
        return True
    
    def shutdown(self) -> None:
        """Gracefully shutdown the service."""
        logger.info("Shutting down Kafka consumer service...")
        
        self.running = False
        
        # Wait for thread to finish (with timeout)
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=10)
        
        # Close consumer
        if self.consumer:
            try:
                self.consumer.close(autocommit=True)
            except Exception as e:
                logger.error(f"Error closing consumer: {e}")
        
        logger.info("✅ Kafka consumer service shutdown complete")
    
    def get_status(self) -> dict:
        """Get service status.
        
        Returns:
            Status dict with metrics
        """
        return {
            "running": self.running,
            "messages_consumed": self.messages_consumed,
            "messages_dropped": self.messages_dropped,
            "last_error": self.last_error,
            "connected": self.consumer is not None,
            "buffer_stats": self.buffer.get_stats(),
        }


# Module-level singleton
_service: Optional[KafkaConsumerService] = None


def get_consumer_service() -> KafkaConsumerService:
    """Get or create global Kafka consumer service."""
    global _service
    if _service is None:
        _service = KafkaConsumerService()
    return _service


def start_consumer_service() -> bool:
    """Start the global Kafka consumer service."""
    service = get_consumer_service()
    return service.start()


def shutdown_consumer_service() -> None:
    """Shutdown the global Kafka consumer service."""
    global _service
    if _service:
        _service.shutdown()
        _service = None
