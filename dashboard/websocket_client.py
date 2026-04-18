"""
WebSocket Client for Streamlit Dashboard
=========================================

Manages WebSocket connection to real-time event server.
Handles reconnection, event buffering, and async operation.

Usage:
    client = WebSocketClient(tenant_id="tenant-1")
    client.connect()
    
    for event in client.get_new_events():
        process_event(event)
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from collections import deque
from typing import Optional, Callable, Any

import websockets
from websockets.client import WebSocketClientProtocol

logger = logging.getLogger(__name__)


class WebSocketClient:
    """
    Async WebSocket client for real-time event streaming.
    
    Features:
    - Automatic reconnection with exponential backoff
    - Event buffering
    - Callback support for async/sync handlers
    - Graceful shutdown
    - Configurable timeout and retry logic
    """
    
    def __init__(
        self,
        server_url: str,
        tenant_id: str = "default",
        token: Optional[str] = None,
        max_buffer_size: int = 10000,
        max_retries: int = 10,
    ):
        """Initialize WebSocket client.
        
        Args:
            server_url: WebSocket server URL (e.g., "ws://localhost:8001/ws/events")
            tenant_id: Tenant ID for event isolation
            token: Optional auth token
            max_buffer_size: Max events to buffer locally
            max_retries: Max reconnection attempts
        """
        self.server_url = f"{server_url}/{tenant_id}"
        if token:
            self.server_url += f"?token={token}"
        
        self.tenant_id = tenant_id
        self.token = token
        self.max_buffer_size = max_buffer_size
        self.max_retries = max_retries
        
        self.websocket: Optional[WebSocketClientProtocol] = None
        self.connected = False
        self.running = False
        
        # Event buffer
        self.event_buffer: deque = deque(maxlen=max_buffer_size)
        self.last_event_timestamp: Optional[str] = None
        
        # Callbacks
        self.on_event: Optional[Callable] = None
        self.on_connect: Optional[Callable] = None
        self.on_disconnect: Optional[Callable] = None
        
        # Thread-safe operations
        self.lock = threading.Lock()
        self.connect_event = asyncio.Event()
        self.task: Optional[asyncio.Task] = None
        
        # Stats
        self.messages_received = 0
        self.messages_dropped = 0
        self.last_error: Optional[str] = None
    
    async def _connect(self) -> bool:
        """Establish WebSocket connection with retry logic.
        
        Returns:
            True if connected, False if failed after retries
        """
        for attempt in range(self.max_retries):
            try:
                logger.info(
                    f"Connecting to WebSocket (attempt {attempt + 1}/{self.max_retries}): {self.server_url}"
                )
                
                self.websocket = await asyncio.wait_for(
                    websockets.connect(
                        self.server_url,
                        ping_interval=20,
                        ping_timeout=10,
                        max_size=10 * 1024 * 1024,  # 10MB max message size
                        compression=None,
                    ),
                    timeout=30.0
                )
                
                self.connected = True
                logger.info(f"✅ Connected to WebSocket: {self.server_url}")
                
                if self.on_connect:
                    try:
                        if asyncio.iscoroutinefunction(self.on_connect):
                            await self.on_connect()
                        else:
                            self.on_connect()
                    except Exception as e:
                        logger.error(f"Error in on_connect callback: {e}")
                
                return True
            
            except asyncio.TimeoutError:
                self.last_error = "Connection timeout"
                logger.warning(f"WebSocket connection timeout (attempt {attempt + 1})")
            
            except Exception as e:
                self.last_error = str(e)
                logger.warning(f"WebSocket connection error: {e}")
            
            if attempt < self.max_retries - 1:
                backoff = min(2 ** attempt, 30)  # Exponential backoff, max 30s
                logger.info(f"Retrying in {backoff}s...")
                await asyncio.sleep(backoff)
        
        logger.error(f"Failed to connect after {self.max_retries} attempts")
        return False
    
    async def _receive_loop(self) -> None:
        """Main receive loop."""
        try:
            while self.running:
                try:
                    if not self.websocket or not self.connected:
                        logger.warning("WebSocket not connected, attempting reconnection...")
                        if await self._connect():
                            continue
                        else:
                            await asyncio.sleep(5)
                            continue
                    
                    # Receive message
                    try:
                        message = await asyncio.wait_for(
                            self.websocket.recv(),
                            timeout=60.0  # Timeout if no data for 60s
                        )
                    except asyncio.TimeoutError:
                        logger.debug("WebSocket receive timeout, sending heartbeat request...")
                        try:
                            await self.websocket.send(
                                json.dumps({"type": "get_events", "limit": 10})
                            )
                        except Exception:
                            pass
                        continue
                    
                    # Parse message
                    try:
                        data = json.loads(message)
                    except json.JSONDecodeError:
                        logger.warning(f"Invalid JSON received: {message[:100]}")
                        self.messages_dropped += 1
                        continue
                    
                    # Handle different message types
                    msg_type = data.get("type", "unknown")
                    
                    if msg_type == "ping":
                        # Server ping
                        try:
                            await self.websocket.send(
                                json.dumps({"type": "pong"})
                            )
                        except Exception as e:
                            logger.debug(f"Error sending pong: {e}")
                    
                    elif msg_type == "event":
                        # Single event
                        event = data.get("data", {})
                        await self._handle_event(event)
                    
                    elif msg_type in ["events", "initial"]:
                        # Event batch
                        events = data.get("events", [])
                        for event in events:
                            await self._handle_event(event)
                    
                    else:
                        logger.debug(f"Unknown message type: {msg_type}")
                
                except websockets.exceptions.ConnectionClosed:
                    logger.warning("WebSocket connection closed")
                    self.connected = False
                    
                    if self.on_disconnect:
                        try:
                            if asyncio.iscoroutinefunction(self.on_disconnect):
                                await self.on_disconnect()
                            else:
                                self.on_disconnect()
                        except Exception as e:
                            logger.error(f"Error in on_disconnect callback: {e}")
                    
                    # Attempt reconnection
                    if self.running and await self._connect():
                        continue
                    else:
                        break
                
                except Exception as e:
                    logger.error(f"Receive loop error: {e}")
                    self.last_error = str(e)
                    await asyncio.sleep(5)
        
        finally:
            self.connected = False
            logger.info("WebSocket receive loop stopped")
    
    async def _handle_event(self, event: dict) -> None:
        """Process received event.
        
        Args:
            event: Event dict
        """
        try:
            # Add to buffer
            with self.lock:
                self.event_buffer.append(event)
                self.last_event_timestamp = event.get("buffer_timestamp")
                self.messages_received += 1
            
            # Call callback
            if self.on_event:
                try:
                    if asyncio.iscoroutinefunction(self.on_event):
                        await self.on_event(event)
                    else:
                        self.on_event(event)
                except Exception as e:
                    logger.error(f"Error in on_event callback: {e}")
        
        except Exception as e:
            logger.error(f"Error handling event: {e}")
            self.messages_dropped += 1
    
    async def connect_async(self) -> bool:
        """Establish connection (async version).
        
        Returns:
            True if connected
        """
        if self.connected:
            return True
        
        success = await self._connect()
        if success:
            self.running = True
            self.task = asyncio.create_task(self._receive_loop())
        
        return success
    
    def connect(self) -> bool:
        """Establish connection (blocking version, runs async in background).
        
        Returns:
            True if connection task started
        """
        # Run async connection in a way that works with Streamlit
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self.running = True
            self.task = loop.create_task(self._receive_loop())
            
            # Start receiving in background
            threading.Thread(target=self._run_async_loop, args=(loop,), daemon=True).start()
            return True
        except Exception as e:
            logger.error(f"Error starting connection: {e}")
            return False
    
    def _run_async_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Run async event loop in thread."""
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._connect_and_receive())
        except Exception as e:
            logger.error(f"Async loop error: {e}")
        finally:
            loop.close()
    
    async def _connect_and_receive(self) -> None:
        """Connect and start receiving loop."""
        if await self._connect():
            await self._receive_loop()
    
    def get_new_events(self) -> list[dict]:
        """Get buffered events (non-blocking).
        
        Returns:
            List of events in buffer
        """
        with self.lock:
            events = list(self.event_buffer)
            self.event_buffer.clear()
            return events
    
    def get_all_events(self) -> list[dict]:
        """Get all buffered events without clearing.
        
        Returns:
            List of events in buffer
        """
        with self.lock:
            return list(self.event_buffer)
    
    async def request_events(
        self,
        since_timestamp: Optional[str] = None,
        limit: int = 100
    ) -> list[dict]:
        """Request events from server (useful for reconnection).
        
        Args:
            since_timestamp: ISO timestamp to fetch events after
            limit: Max events to fetch
            
        Returns:
            List of events
        """
        if not self.websocket or not self.connected:
            logger.warning("Not connected, cannot request events")
            return []
        
        try:
            await self.websocket.send(
                json.dumps({
                    "type": "get_events",
                    "since_timestamp": since_timestamp,
                    "limit": limit
                })
            )
            return []  # Server will send events via normal flow
        except Exception as e:
            logger.error(f"Error requesting events: {e}")
            return []
    
    def disconnect(self) -> None:
        """Disconnect WebSocket."""
        logger.info("Disconnecting WebSocket...")
        self.running = False
        
        if self.websocket:
            try:
                # Close will happen in the receive loop
                pass
            except Exception as e:
                logger.error(f"Error closing WebSocket: {e}")
    
    def get_status(self) -> dict[str, Any]:
        """Get client status.
        
        Returns:
            Status dict
        """
        return {
            "connected": self.connected,
            "running": self.running,
            "tenant_id": self.tenant_id,
            "messages_received": self.messages_received,
            "messages_dropped": self.messages_dropped,
            "buffered_events": len(self.event_buffer),
            "last_event_timestamp": self.last_event_timestamp,
            "last_error": self.last_error,
        }
