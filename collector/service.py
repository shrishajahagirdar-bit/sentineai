from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from collector.events import WindowsEventCollector
from collector.filesystem import FileActivityCollector
from collector.network import NetworkCollector
from collector.processes import ProcessCollector
from collector.storage import append_jsonl, ensure_storage, read_jsonl
from core.transformers import normalize_event
from ml_engine.training import train_models
from risk_engine.engine import RiskPipeline
from sentinel_config import CONFIG


class SentinelCollectorService:
    def __init__(self) -> None:
        ensure_storage()
        self.event_collector = WindowsEventCollector()
        self.process_collector = ProcessCollector()
        self.network_collector = NetworkCollector()
        self.file_collector = FileActivityCollector()
        self.risk = RiskPipeline()
        self.cycles = 0

    def start(self) -> list[dict[str, Any]]:
        startup_events = self.file_collector.start()
        for event in startup_events:
            append_jsonl(CONFIG.event_store, normalize_event(event))
        return startup_events

    def collect_once(self) -> list[dict[str, Any]]:
        self.cycles += 1
        batch: list[dict[str, Any]] = []
        batch.extend(self.event_collector.collect())
        batch.extend(self.process_collector.collect())
        batch.extend(self.network_collector.collect())
        batch.extend(self.file_collector.collect())

        if not batch:
            batch.append(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source": "sentinel",
                    "event_type": "heartbeat",
                    "status": "ok",
                    "user": "system",
                    "message": "No new telemetry during this polling cycle.",
                }
            )

        for event in batch:
            normalized_event = normalize_event(event)
            append_jsonl(CONFIG.event_store, normalized_event)
            if normalized_event.get("status") == "ok" and normalized_event.get("event_type") != "heartbeat":
                self.risk.assess(normalized_event, persist=True)

        self.risk.ueba.rebuild()
        if self.cycles % 20 == 0:
            metadata = train_models(min_events=50)
            if metadata.get("status") == "trained":
                self.risk.refresh_models()

        self._trim_event_store()
        return batch

    def run_forever(self) -> None:
        self.start()
        self._bootstrap_models_if_possible()

        while True:
            self.collect_once()
            time.sleep(CONFIG.poll_interval_seconds)

    def shutdown(self) -> None:
        self.file_collector.stop()

    def _bootstrap_models_if_possible(self) -> None:
        observed = len(read_jsonl(CONFIG.event_store, limit=None))
        if observed >= 50:
            train_models(min_events=50)
            self.risk.refresh_models()

    @staticmethod
    def _trim_event_store() -> None:
        records = read_jsonl(CONFIG.event_store, limit=None)
        if len(records) <= CONFIG.max_events:
            return
        trimmed = records[-CONFIG.max_events :]
        CONFIG.event_store.write_text("", encoding="utf-8")
        for record in trimmed:
            append_jsonl(CONFIG.event_store, record)
