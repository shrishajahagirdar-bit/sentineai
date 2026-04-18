from __future__ import annotations

import queue
import threading
from datetime import datetime, timezone
from typing import Any

from agent.core.normalizer import build_event


class ETWCollector(threading.Thread):
    def __init__(
        self,
        config: Any,
        output_queue: "queue.Queue[dict[str, Any]]",
        logger: Any,
        stop_event: threading.Event,
    ) -> None:
        super().__init__(name="etw-collector", daemon=True)
        self.config = config
        self.output_queue = output_queue
        self.logger = logger
        self.stop_event = stop_event

    def run(self) -> None:
        while not self.stop_event.is_set():
            self.stop_event.wait(max(self.config.event_poll_seconds, 5.0))

    def emit_high_level_signal(self, *, user: str, process_name: str, reason: str) -> None:
        event = build_event(
            self.config,
            user=user,
            event_source="windows_event",
            event_type="etw_signal",
            severity="high",
            raw_data={
                "provider": "etw",
                "reason": reason,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "signal_type": "process_injection_suspected",
            },
            process_name=process_name,
        )
        try:
            self.output_queue.put_nowait(event)
        except queue.Full:
            self.logger.warning("agent queue full", extra={"payload": {"collector": "etw", "event_type": "etw_signal"}})
