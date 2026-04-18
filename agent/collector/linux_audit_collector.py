from __future__ import annotations

import queue
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent.core.normalizer import build_event


class LinuxAuditCollector(threading.Thread):
    def __init__(
        self,
        config: Any,
        output_queue: "queue.Queue[dict[str, Any]]",
        logger: Any,
        stop_event: threading.Event,
    ) -> None:
        super().__init__(name="linux-audit-collector", daemon=True)
        self.config = config
        self.output_queue = output_queue
        self.logger = logger
        self.stop_event = stop_event
        self.sources = [Path("/var/log/audit/audit.log"), Path("/var/log/syslog")]
        self.offsets: dict[str, int] = {}

    def run(self) -> None:
        while not self.stop_event.is_set():
            self._collect()
            self.stop_event.wait(max(self.config.event_poll_seconds, 3.0))

    def _collect(self) -> None:
        for source in self.sources:
            if not source.exists():
                continue
            try:
                with source.open("r", encoding="utf-8", errors="ignore") as handle:
                    handle.seek(self.offsets.get(str(source), 0))
                    for line in handle:
                        lowered = line.lower()
                        if "audit" not in lowered and "failed password" not in lowered and "sudo" not in lowered:
                            continue
                        event = build_event(
                            self.config,
                            user="unknown",
                            event_source="windows_event",
                            event_type="linux_audit_event",
                            severity="medium",
                            raw_data={"source": str(source), "message": line.strip()[:2000]},
                            timestamp=datetime.now(timezone.utc).isoformat(),
                        )
                        self.output_queue.put_nowait(event)
                    self.offsets[str(source)] = handle.tell()
            except Exception as exc:
                self.logger.warning("linux audit collection warning", extra={"payload": {"error": str(exc), "collector": "linux_audit"}})
