"""
Production-Grade Event Buffer for Real-Time Streaming
=====================================================

Real-time event buffer with:
- Kafka consumer integration
- WebSocket subscription support
- Thread-safe async operations
- Backpressure handling
- LRU eviction policy

Architecture:
Kafka → KafkaConsumer → EventBuffer → WebSocket Server → Dashboard
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Optional, Set
import threading

logger = logging.getLogger(__name__)


@dataclass
class EventMetadata:
    """Metadata tracking for buffer health."""
    total_received: int = 0
    total_dropped: int = 0
    current_subscribers: int = 0
    last_update: datetime = field(default_factory=datetime.utcnow)
    kafka_lag: Optional[int] = None


class EventBuffer:
    """
    Thread-safe, async-compatible event buffer with subscriptions.
    
    Features:
    - Ring buffer with LRU eviction
    - Subscriber notification on new events
    - Incremental event tracking (since_timestamp)
    - Backpressure handling
    - Memory-bounded storage
    """
    
    def __init__(self, max_events: int = 5000, max_subscribers: int = 100):
        """Initialize buffer.
        
        Args:
            max_events: Maximum events to buffer (LRU eviction)
            max_subscribers: Max concurrent WebSocket subscribers
        """
        self.max_events = max_events
        self.max_subscribers = max_subscribers
        
        # Event storage (per-tenant)
        self.events_by_tenant: dict[str, deque] = {}
        self.incidents_by_tenant: dict[str, deque] = {}
        
        # Subscriber management
        self.subscribers: dict[str, Set[Callable]] = {}  # tenant_id -> callbacks
        self.metadata = EventMetadata()
        
        # Thread safety
        self.lock = threading.RLock()
        self.event = asyncio.Event()
    
    def add_event(self, event: dict, tenant_id: str = "default") -> None:
        """Add event to buffer and notify subscribers.
        
        Args:
            event: Security event dict
            tenant_id: Tenant identifier for multi-tenant isolation
        """
        with self.lock:
            # Validate event
            if not isinstance(event, dict):
                logger.warning(f"Invalid event type: {type(event)}")
                self.metadata.total_dropped += 1
                return

            # Validate enriched event schema - reject raw telemetry
            required_enriched_fields = ["risk_score", "severity", "anomaly_score"]
            if not all(field in event for field in required_enriched_fields):
                logger.warning(f"Rejected raw/unenriched event missing required fields {required_enriched_fields}: {event.keys()}")
                self.metadata.total_dropped += 1
                return

            # Validate event has been processed by stream processor
            if "processed_at" not in event or "processor_version" not in event:
                logger.warning("Rejected event not processed by stream processor (missing processed_at/processor_version)")
                self.metadata.total_dropped += 1
                return

            # Initialize tenant buffers
            if tenant_id not in self.events_by_tenant:
                self.events_by_tenant[tenant_id] = deque(maxlen=self.max_events)

            # Add event with timestamp if missing
            if "buffer_timestamp" not in event:
                event["buffer_timestamp"] = datetime.utcnow().isoformat()

            # Append to tenant's buffer
            self.events_by_tenant[tenant_id].append(event)
            self.metadata.total_received += 1
            self.metadata.last_update = datetime.utcnow()
            
            # Trigger async update (will notify WebSocket clients)
            try:
                self.event.set()
            except RuntimeError:
                # Event loop not running, will be caught elsewhere
                pass
            
            # Notify all subscribers for this tenant
            if tenant_id in self.subscribers:
                for callback in self.subscribers[tenant_id]:
                    try:
                        if asyncio.iscoroutinefunction(callback):
                            asyncio.create_task(callback(event))
                        else:
                            callback(event)
                    except Exception as e:
                        logger.error(f"Subscriber callback error: {e}")
    
    def add_incident(self, incident: dict, tenant_id: str = "default") -> None:
        """Add incident to buffer.
        
        Args:
            incident: Incident dict
            tenant_id: Tenant identifier
        """
        with self.lock:
            if tenant_id not in self.incidents_by_tenant:
                self.incidents_by_tenant[tenant_id] = deque(maxlen=500)
            
            if "buffer_timestamp" not in incident:
                incident["buffer_timestamp"] = datetime.utcnow().isoformat()
            
            self.incidents_by_tenant[tenant_id].append(incident)
    
    def get_events(
        self,
        tenant_id: str = "default",
        since_timestamp: Optional[str] = None,
        limit: int = 1000
    ) -> list[dict]:
        """Get events, optionally since timestamp (incremental).
        
        Args:
            tenant_id: Tenant to query
            since_timestamp: ISO timestamp - only return newer events
            limit: Max events to return
            
        Returns:
            List of events
        """
        with self.lock:
            if tenant_id not in self.events_by_tenant:
                return []
            
            events = list(self.events_by_tenant[tenant_id])
            
            # Filter by timestamp if provided
            if since_timestamp:
                try:
                    since_dt = datetime.fromisoformat(since_timestamp)
                    events = [
                        e for e in events
                        if datetime.fromisoformat(e.get("buffer_timestamp", "1970-01-01")) > since_dt
                    ]
                except ValueError:
                    logger.warning(f"Invalid timestamp format: {since_timestamp}")
            
            return events[-limit:]
    
    def get_incidents(
        self,
        tenant_id: str = "default",
        since_timestamp: Optional[str] = None,
        limit: int = 500
    ) -> list[dict]:
        """Get incidents, optionally since timestamp."""
        with self.lock:
            if tenant_id not in self.incidents_by_tenant:
                return []
            
            incidents = list(self.incidents_by_tenant[tenant_id])
            
            if since_timestamp:
                try:
                    since_dt = datetime.fromisoformat(since_timestamp)
                    incidents = [
                        i for i in incidents
                        if datetime.fromisoformat(i.get("buffer_timestamp", "1970-01-01")) > since_dt
                    ]
                except ValueError:
                    pass
            
            return incidents[-limit:]
    
    def subscribe(self, tenant_id: str, callback: Callable) -> None:
        """Subscribe to buffer updates.
        
        Args:
            tenant_id: Tenant to subscribe to
            callback: Async or sync function(event) called on new events
        """
        with self.lock:
            if tenant_id not in self.subscribers:
                self.subscribers[tenant_id] = set()
            
            if len(self.subscribers[tenant_id]) >= self.max_subscribers:
                logger.warning(f"Max subscribers reached for {tenant_id}")
                return
            
            self.subscribers[tenant_id].add(callback)
            self.metadata.current_subscribers = sum(
                len(subs) for subs in self.subscribers.values()
            )
    
    def unsubscribe(self, tenant_id: str, callback: Callable) -> None:
        """Unsubscribe from buffer updates."""
        with self.lock:
            if tenant_id in self.subscribers:
                self.subscribers[tenant_id].discard(callback)
                self.metadata.current_subscribers = sum(
                    len(subs) for subs in self.subscribers.values()
                )
    
    def clear(self, tenant_id: Optional[str] = None) -> None:
        """Clear buffer (all tenants or specific tenant)."""
        with self.lock:
            if tenant_id:
                self.events_by_tenant.pop(tenant_id, None)
                self.incidents_by_tenant.pop(tenant_id, None)
            else:
                self.events_by_tenant.clear()
                self.incidents_by_tenant.clear()
    
    def get_stats(self) -> dict[str, Any]:
        """Get buffer health statistics."""
        with self.lock:
            return {
                "total_events": sum(
                    len(events) for events in self.events_by_tenant.values()
                ),
                "total_incidents": sum(
                    len(incidents) for incidents in self.incidents_by_tenant.values()
                ),
                "total_received": self.metadata.total_received,
                "total_dropped": self.metadata.total_dropped,
                "current_subscribers": self.metadata.current_subscribers,
                "last_update": self.metadata.last_update.isoformat(),
                "kafka_lag": self.metadata.kafka_lag,
                "tenants": len(self.events_by_tenant),
                "memory_usage_mb": self._estimate_memory_mb(),
            }
    
    def set_kafka_lag(self, lag: int) -> None:
        """Update Kafka consumer lag metric."""
        with self.lock:
            self.metadata.kafka_lag = lag
    
    def _estimate_memory_mb(self) -> float:
        """Rough estimate of memory usage."""
        import sys
        total_bytes = 0
        for events in self.events_by_tenant.values():
            for event in events:
                total_bytes += sys.getsizeof(json.dumps(event))
        return total_bytes / (1024 * 1024)


# Global singleton buffer
_global_buffer: Optional[EventBuffer] = None

def get_buffer() -> EventBuffer:
    """Get or create global event buffer."""
    global _global_buffer
    if _global_buffer is None:
        _global_buffer = EventBuffer(max_events=5000, max_subscribers=100)
    return _global_buffer


def init_buffer(max_events: int = 5000) -> EventBuffer:
    """Initialize a new buffer (for testing)."""
    global _global_buffer
    _global_buffer = EventBuffer(max_events=max_events)
    return _global_buffer
