from __future__ import annotations

import queue
import threading
from typing import Any

from agent.collector.windows_event_collector import WindowsEventCollector


class SysmonCollector(WindowsEventCollector):
    def __init__(
        self,
        config: Any,
        output_queue: "queue.Queue[dict[str, Any]]",
        logger: Any,
        stop_event: threading.Event,
    ) -> None:
        super().__init__(config, output_queue, logger, stop_event)
        self.name = "sysmon-collector"
        self.log_names = ["Microsoft-Windows-Sysmon/Operational"]
