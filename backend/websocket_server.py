"""
WebSocket Server for Real-Time Event Streaming
==============================================

FastAPI WebSocket endpoint for real-time event push to dashboard clients.

Features:
- Per-tenant event isolation
- Multi-client support
- Automatic reconnection
- Heartbeat ping/pong
- Backpressure handling
- Dead client cleanup

Endpoint: ws://host:8001/ws/events/{tenant_id}

Usage:
    python backend/websocket_server.py
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from dashboard.data_buffer import get_buffer
from sentinel_config import CONFIG

from backend.timeline_api import include_timeline_routes
from edr_behavior.attack_chain_correlator import get_correlator, init_correlator
from edr_behavior.replay_engine import get_replay_engine, init_replay_engine
from edr_behavior.timeline_store import get_timeline_store, init_timeline_store

# Initialize alert Kafka consumer
from backend.alerting import alert_kafka_consumer

logger = logging.getLogger(__name__)

app = FastAPI(
    title="SentinelAI Real-Time Event Server",
    description="WebSocket endpoint for real-time event streaming",
    version="1.0.0"
)

# Enable CORS for dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize timeline backend for HTTP API integration
store = init_timeline_store()
replay_engine = init_replay_engine()
correlator = init_correlator(store)
include_timeline_routes(app, store=store, replay_engine=replay_engine, correlator=correlator)


@app.get("/")
async def root() -> RedirectResponse:
    return RedirectResponse(url="/docs")


class EventBroadcaster:
    """Manages WebSocket connections per tenant.
    
    Broadcasts EventBuffer updates to all connected clients for a tenant.
    """
    
    def __init__(self):
        """Initialize broadcaster."""
        self.connections: dict[str, Set[WebSocket]] = {}  # tenant_id -> connections
        self.lock = asyncio.Lock()
        self.buffer = get_buffer()
        self._tasks: Set[asyncio.Task] = set()
    
    async def connect(self, websocket: WebSocket, tenant_id: str) -> None:
        """Register a new WebSocket connection.
        
        Args:
            websocket: WebSocket connection
            tenant_id: Tenant identifier
        """
        await websocket.accept()
        
        async with self.lock:
            if tenant_id not in self.connections:
                self.connections[tenant_id] = set()
            
            self.connections[tenant_id].add(websocket)
        
        logger.info(
            f"Client connected: {websocket.client} | Tenant: {tenant_id} | "
            f"Total clients: {len(self.connections.get(tenant_id, set()))}"
        )
        
        # Send initial event batch
        events = self.buffer.get_events(tenant_id=tenant_id, limit=100)
        try:
            await websocket.send_json({
                "type": "initial",
                "events": events,
                "count": len(events)
            })
        except Exception as e:
            logger.error(f"Error sending initial events: {e}")
    
    async def disconnect(self, websocket: WebSocket, tenant_id: str) -> None:
        """Unregister a WebSocket connection.
        
        Args:
            websocket: WebSocket connection
            tenant_id: Tenant identifier
        """
        async with self.lock:
            if tenant_id in self.connections:
                self.connections[tenant_id].discard(websocket)
                
                if not self.connections[tenant_id]:
                    del self.connections[tenant_id]
        
        logger.info(
            f"Client disconnected: {websocket.client} | Tenant: {tenant_id} | "
            f"Remaining clients: {len(self.connections.get(tenant_id, set()))}"
        )
    
    async def broadcast(self, event: dict, tenant_id: str) -> None:
        """Broadcast event to all clients for a tenant.
        
        Args:
            event: Event dict to broadcast
            tenant_id: Tenant identifier
        """
        async with self.lock:
            if tenant_id not in self.connections:
                return
            
            connections = list(self.connections[tenant_id])
        
        # Send to all clients (async, non-blocking)
        message = {
            "type": "event",
            "data": event,
            "timestamp": event.get("buffer_timestamp", "")
        }
        
        dead_connections = []
        
        for websocket in connections:
            try:
                await asyncio.wait_for(
                    websocket.send_json(message),
                    timeout=5.0  # Backpressure: timeout slow clients
                )
            except asyncio.TimeoutError:
                logger.warning(f"WebSocket send timeout: {websocket.client}")
                dead_connections.append(websocket)
            except Exception as e:
                logger.debug(f"Error broadcasting to {websocket.client}: {e}")
                dead_connections.append(websocket)
        
        # Clean up dead connections
        async with self.lock:
            for ws in dead_connections:
                self.connections[tenant_id].discard(ws)
    
    async def heartbeat(self, websocket: WebSocket, tenant_id: str) -> None:
        """Send periodic heartbeat to keep connection alive.
        
        Args:
            websocket: WebSocket connection
            tenant_id: Tenant identifier
        """
        try:
            while True:
                await asyncio.sleep(30)  # Heartbeat every 30 seconds
                try:
                    await websocket.send_json({"type": "ping"})
                except Exception as e:
                    logger.debug(f"Heartbeat send error: {e}")
                    break
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Heartbeat error: {e}")
    
    async def event_listener(self, tenant_id: str) -> None:
        """Subscribe to EventBuffer updates.
        
        Broadcasts new events to all connected clients.
        
        Args:
            tenant_id: Tenant to listen for
        """
        async def on_event(event: dict) -> None:
            """Callback when event arrives in EventBuffer."""
            await self.broadcast(event, tenant_id)
        
        # Register callback with EventBuffer
        self.buffer.subscribe(tenant_id, on_event)


# Global broadcaster instance
broadcaster = EventBroadcaster()


@app.websocket("/ws/events/{tenant_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    tenant_id: str,
    token: Optional[str] = Query(None)
) -> None:
    """WebSocket endpoint for real-time event streaming.
    
    Args:
        websocket: WebSocket connection
        tenant_id: Tenant identifier
        token: Optional auth token (for future authentication)
    
    Example:
        ws = await websockets.connect("ws://localhost:8001/ws/events/tenant-1")
        async for msg in ws:
            print(json.loads(msg))
    """
    await broadcaster.connect(websocket, tenant_id)
    
    # Start heartbeat task
    heartbeat_task = asyncio.create_task(
        broadcaster.heartbeat(websocket, tenant_id)
    )
    
    # Start event listener task
    listener_task = asyncio.create_task(
        broadcaster.event_listener(tenant_id)
    )
    
    try:
        # Listen for incoming messages from client
        while True:
            try:
                data = await asyncio.wait_for(
                    websocket.receive_json(),
                    timeout=300.0  # 5-minute timeout
                )
                
                # Handle client messages (e.g., "pong", filters, etc.)
                msg_type = data.get("type", "unknown")
                
                if msg_type == "pong":
                    logger.debug(f"Pong from {websocket.client}")
                
                elif msg_type == "get_events":
                    # Client requests event batch
                    since_timestamp = data.get("since_timestamp")
                    limit = data.get("limit", 100)
                    events = broadcaster.buffer.get_events(
                        tenant_id=tenant_id,
                        since_timestamp=since_timestamp,
                        limit=limit
                    )
                    await websocket.send_json({
                        "type": "events",
                        "data": events,
                        "count": len(events)
                    })
                
                else:
                    logger.debug(f"Unknown message type: {msg_type}")
            
            except asyncio.TimeoutError:
                logger.debug(f"Client {websocket.client} idle timeout")
                break
            
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON from {websocket.client}")
                continue
    
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnect: {websocket.client}")
    
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    
    finally:
        # Cleanup
        await broadcaster.disconnect(websocket, tenant_id)
        heartbeat_task.cancel()
        listener_task.cancel()
        
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass
        
        try:
            await listener_task
        except asyncio.CancelledError:
            pass


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    buffer_stats = broadcaster.buffer.get_stats()
    return {
        "status": "healthy",
        "service": "sentinelai-websocket-server",
        "buffer": buffer_stats,
        "connections": {
            tenant_id: len(conns)
            for tenant_id, conns in broadcaster.connections.items()
        }
    }


@app.get("/stats")
async def stats():
    """Get server statistics."""
    return {
        "buffer_stats": broadcaster.buffer.get_stats(),
        "active_connections": sum(
            len(conns) for conns in broadcaster.connections.values()
        ),
        "tenants": len(broadcaster.connections),
        "connection_breakdown": {
            tenant_id: len(conns)
            for tenant_id, conns in broadcaster.connections.items()
        }
    }


if __name__ == "__main__":
    import uvicorn
    import threading
    
    logger.info("Starting SentinelAI WebSocket Server...")
    logger.info(f"WebSocket endpoint: ws://localhost:8001/ws/events/{{tenant_id}}")
    logger.info(f"Health check: http://localhost:8001/health")
    logger.info(f"Statistics: http://localhost:8001/stats")
    
    # Start alert Kafka consumer in background thread
    alert_thread = threading.Thread(
        target=alert_kafka_consumer.consume,
        daemon=True,
        name="alert-kafka-consumer"
    )
    alert_thread.start()
    logger.info("Alert Kafka consumer started in background thread")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8001,
        log_level="info",
        access_log=True,
    )
