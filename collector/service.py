from __future__ import annotations

import time
from typing import Any

from collector.events import WindowsEventCollector
from collector.sessions import SessionCollector
from collector.network import NetworkCollector
from collector.processes import ProcessCollector
from collector.auth.windows_auth_collector import WindowsAuthCollector
from collector.storage import ensure_storage, append_jsonl
from core.transformers import normalize_event
from core.safe_wrapper import log_health_event
from ml_engine.ueba_transformer import UebaEventTransformer
from ml_engine.ueba_filter import UebaEventFilter
from kafka.producer import SecurityLogsProducer
from sentinel_config import CONFIG


class SentinelCollectorService:
    """
    Main collector service that orchestrates:
    1. Windows Authentication Collection (for UEBA)
    2. System Event Collection (for EDR)
    3. Process/Network Collection (for behavioral analysis)
    
    Critical design: Auth events are:
    - Collected separately
    - Transformed to UEBA format
    - Filtered for identity relevance
    - Stored in auth_event_store
    - Processed by UEBA baseline engine
    """

    def __init__(self) -> None:
        ensure_storage()
        
        # Core collectors
        self.event_collector = WindowsEventCollector()
        self.session_collector = SessionCollector()
        self.process_collector = ProcessCollector()
        self.network_collector = NetworkCollector()
        
        # UEBA-specific collector and pipeline
        self.auth_collector = WindowsAuthCollector()
        self.ueba_transformer = UebaEventTransformer()
        self.ueba_filter = UebaEventFilter()
        
        # Kafka producer
        self.producer = SecurityLogsProducer()

    def start(self) -> list[dict[str, Any]]:
        return []

    def collect_once(self) -> list[dict[str, Any]]:
        """
        Collect telemetry in one cycle.
        
        Pipeline:
        1. Collect Windows auth events
        2. Transform to UEBA format
        3. Filter for identity relevance
        4. Store separately for UEBA processing
        5. Collect all other telemetry normally
        """
        batch: list[dict[str, Any]] = []
        
        # ===== UEBA Pipeline =====
        auth_events = self.auth_collector.collect()
        if auth_events:
            # Transform raw auth events to UEBA format
            transformed_auth = self.ueba_transformer.batch_transform(auth_events)
            
            # Filter for UEBA relevance (only identity events)
            filtered_auth = self.ueba_filter.batch_filter(transformed_auth)
            
            if filtered_auth:
                # Store in separate auth event store for UEBA processing
                for auth_event in filtered_auth:
                    append_jsonl(CONFIG.auth_event_store, auth_event)
                
                # Also publish to Kafka for streaming UEBA processing
                self.producer.publish_batch(filtered_auth)
                
                log_health_event(
                    "debug",
                    "ueba_collection",
                    f"Collected and filtered {len(filtered_auth)} auth events",
                    context={"count": len(filtered_auth)},
                )

        # ===== Standard EDR Telemetry =====
        batch.extend(self.event_collector.collect())
        batch.extend(self.session_collector.collect())
        batch.extend(self.process_collector.collect())
        batch.extend(self.network_collector.collect())
        
        # Normalize and publish all telemetry
        normalized_batch = [
            normalize_event(event) for event in batch if isinstance(event, dict)
        ]
        if normalized_batch:
            self.producer.publish_batch(normalized_batch)

        return normalized_batch

    def run_forever(self) -> None:
        """Run collector in continuous loop."""
        self.start()

        while True:
            self.collect_once()
            time.sleep(CONFIG.poll_interval_seconds)

    def shutdown(self) -> None:
        """Gracefully shutdown collector."""
        log_health_event(
            "info", "collector_shutdown", "Sentinel collector stopped."
        )

