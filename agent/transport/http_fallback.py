"""
HTTP Fallback Transport for Windows Telemetry

Provides HTTP-based event streaming when Kafka is unavailable.
Includes local buffering and retry logic for reliability.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent.core.logging import configure_logger

try:
    import aiohttp
except ImportError:
    aiohttp = None


class HTTPFallbackTransport:
    """
    HTTP fallback transport for event streaming.

    When Kafka is unavailable, buffers events locally and sends via HTTP POST
    to a fallback endpoint. Includes retry logic and circuit breaker pattern.
    """

    def __init__(
        self,
        endpoint_url: str,
        buffer_file: Path,
        max_buffer_size: int = 10000,
        batch_size: int = 50,
        retry_attempts: int = 3,
        retry_delay: float = 1.0,
        circuit_breaker_threshold: int = 5,
        circuit_breaker_timeout: float = 60.0,
    ):
        self.endpoint_url = endpoint_url
        self.buffer_file = buffer_file
        self.max_buffer_size = max_buffer_size
        self.batch_size = batch_size
        self.retry_attempts = retry_attempts
        self.retry_delay = retry_delay

        # Circuit breaker state
        self.circuit_breaker_failures = 0
        self.circuit_breaker_threshold = circuit_breaker_threshold
        self.circuit_breaker_timeout = circuit_breaker_timeout
        self.circuit_breaker_last_failure = 0.0

        # HTTP session
        self.session: Optional[aiohttp.ClientSession] = None

        # Statistics
        self.stats = {
            "events_buffered": 0,
            "events_sent": 0,
            "batches_sent": 0,
            "failed_sends": 0,
            "circuit_breaker_trips": 0,
        }

        self.logger = logging.getLogger("http_fallback")

    async def initialize(self) -> None:
        """Initialize the HTTP transport."""
        if aiohttp is None:
            self.logger.warning("aiohttp not available, HTTP fallback disabled")
            return

        # Create HTTP session with timeouts
        timeout = aiohttp.ClientTimeout(total=10.0, connect=5.0)
        self.session = aiohttp.ClientSession(timeout=timeout)

        self.logger.info("HTTP fallback transport initialized", extra={
            "endpoint": self.endpoint_url,
            "buffer_file": str(self.buffer_file),
        })

    async def send_batch(self, events: List[Dict[str, Any]]) -> bool:
        """
        Send a batch of events via HTTP.

        Returns True if successful, False otherwise.
        """
        if not self.session or self._circuit_breaker_open():
            # Buffer events locally
            await self._buffer_events(events)
            return False

        try:
            # Send via HTTP with retries
            success = await self._send_with_retry(events)
            if success:
                self._record_success()
                self.stats["events_sent"] += len(events)
                self.stats["batches_sent"] += 1
                return True
            else:
                self._record_failure()
                await self._buffer_events(events)
                return False

        except Exception as exc:
            self._record_failure()
            await self._buffer_events(events)
            self.logger.error(f"HTTP send failed: {exc}")
            return False

    async def _send_with_retry(self, events: List[Dict[str, Any]]) -> bool:
        """Send events with retry logic."""
        for attempt in range(self.retry_attempts):
            try:
                payload = {"events": events}

                async with self.session.post(
                    self.endpoint_url,
                    json=payload,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "SentinelAI-Windows-Agent/1.0",
                    }
                ) as response:
                    if response.status in {200, 201, 202}:
                        return True
                    else:
                        self.logger.warning(f"HTTP {response.status}: {await response.text()}")

            except Exception as exc:
                if attempt < self.retry_attempts - 1:
                    self.logger.debug(f"HTTP attempt {attempt + 1} failed: {exc}")
                    await asyncio.sleep(self.retry_delay * (2 ** attempt))  # Exponential backoff
                else:
                    self.logger.error(f"All HTTP attempts failed: {exc}")

        return False

    async def _buffer_events(self, events: List[Dict[str, Any]]) -> None:
        """Buffer events to local file."""
        try:
            # Ensure buffer directory exists
            self.buffer_file.parent.mkdir(parents=True, exist_ok=True)

            # Append events to buffer file
            with open(self.buffer_file, 'a', encoding='utf-8') as f:
                for event in events:
                    json.dump(event, f, ensure_ascii=False)
                    f.write('\n')

            self.stats["events_buffered"] += len(events)
            self.logger.debug(f"Buffered {len(events)} events to {self.buffer_file}")

        except Exception as exc:
            self.logger.error(f"Failed to buffer events: {exc}")

    async def replay_buffered_events(self) -> int:
        """
        Replay buffered events when connection is restored.

        Returns the number of events successfully replayed.
        """
        if not self.session or not self.buffer_file.exists():
            return 0

        replayed_count = 0

        try:
            # Read buffered events
            buffered_events = []
            with open(self.buffer_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            event = json.loads(line)
                            buffered_events.append(event)
                        except json.JSONDecodeError:
                            self.logger.warning(f"Invalid JSON in buffer: {line}")

            if not buffered_events:
                return 0

            self.logger.info(f"Replaying {len(buffered_events)} buffered events")

            # Send in batches
            batch = []
            for event in buffered_events:
                batch.append(event)
                if len(batch) >= self.batch_size:
                    if await self.send_batch(batch):
                        replayed_count += len(batch)
                    batch = []

            # Send remaining events
            if batch and await self.send_batch(batch):
                replayed_count += len(batch)

            # Clear buffer file if all events were sent
            if replayed_count == len(buffered_events):
                self.buffer_file.unlink()
                self.logger.info("Buffer file cleared after successful replay")
            else:
                # Keep only unsent events
                remaining_events = buffered_events[replayed_count:]
                with open(self.buffer_file, 'w', encoding='utf-8') as f:
                    for event in remaining_events:
                        json.dump(event, f, ensure_ascii=False)
                        f.write('\n')

        except Exception as exc:
            self.logger.error(f"Failed to replay buffered events: {exc}")

        return replayed_count

    def _circuit_breaker_open(self) -> bool:
        """Check if circuit breaker is open."""
        if self.circuit_breaker_failures >= self.circuit_breaker_threshold:
            current_time = time.time()
            if current_time - self.circuit_breaker_last_failure < self.circuit_breaker_timeout:
                return True
            else:
                # Reset circuit breaker
                self.circuit_breaker_failures = 0
                self.logger.info("HTTP circuit breaker reset")
        return False

    def _record_success(self) -> None:
        """Record a successful HTTP request."""
        self.circuit_breaker_failures = 0

    def _record_failure(self) -> None:
        """Record a failed HTTP request."""
        self.circuit_breaker_failures += 1
        self.circuit_breaker_last_failure = time.time()
        self.stats["failed_sends"] += 1

        if self.circuit_breaker_failures >= self.circuit_breaker_threshold:
            self.stats["circuit_breaker_trips"] += 1
            self.logger.warning("HTTP circuit breaker opened")

    async def close(self) -> None:
        """Close the HTTP transport."""
        if self.session:
            await self.session.close()
            self.session = None

        self.logger.info("HTTP fallback transport closed", extra=self.stats)

    def get_stats(self) -> Dict[str, Any]:
        """Get transport statistics."""
        return dict(self.stats)

    def get_buffer_size(self) -> int:
        """Get the current buffer size."""
        try:
            if self.buffer_file.exists():
                with open(self.buffer_file, 'r', encoding='utf-8') as f:
                    return sum(1 for _ in f)
        except Exception:
            pass
        return 0


# Global HTTP fallback instance
_http_fallback_instance: Optional[HTTPFallbackTransport] = None


async def get_http_fallback(
    endpoint_url: str = "http://localhost:8010/ingest",
    buffer_file: Path = Path("windows_events_buffer.jsonl")
) -> HTTPFallbackTransport:
    """Get or create global HTTP fallback instance."""
    global _http_fallback_instance

    if _http_fallback_instance is None:
        _http_fallback_instance = HTTPFallbackTransport(
            endpoint_url=endpoint_url,
            buffer_file=buffer_file,
        )
        await _http_fallback_instance.initialize()

    return _http_fallback_instance


async def replay_buffered_events() -> int:
    """Replay any buffered events."""
    global _http_fallback_instance

    if _http_fallback_instance:
        return await _http_fallback_instance.replay_buffered_events()
    return 0


async def close_http_fallback() -> None:
    """Close the global HTTP fallback instance."""
    global _http_fallback_instance

    if _http_fallback_instance:
        await _http_fallback_instance.close()
        _http_fallback_instance = None