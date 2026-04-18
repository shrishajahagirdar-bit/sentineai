from __future__ import annotations

import queue
import threading
import time
from typing import Any

from agent.control_plane_client import ControlPlaneClient
from agent.collector.network_collector import NetworkCollector
from agent.collector.process_collector import ProcessCollector
from agent.collector.sysmon_collector import SysmonCollector
from agent.collector.etw_collector import ETWCollector
from agent.collector.linux_audit_collector import LinuxAuditCollector
from agent.collector.windows_event_collector import WindowsEventCollector
from agent.core.config import AgentConfig
from agent.core.logging import configure_logger
from agent.core.normalizer import heartbeat_event
from agent.transport.kafka_producer import KafkaEventTransport
from observability.context import set_correlation_id, set_tenant_id
from observability.metrics import SERVICE_HEALTH

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


class WindowsEDRAgent:
    def __init__(self, config: AgentConfig | None = None) -> None:
        base_config = config or AgentConfig.load()
        base_config.ensure_directories()
        bootstrap_logger = configure_logger(base_config.log_path)
        self.control_plane = ControlPlaneClient(base_config, bootstrap_logger)
        self.config = self.control_plane.enroll()
        self.config.ensure_directories()
        self.logger = configure_logger(self.config.log_path)
        self.stop_event = threading.Event()
        self.event_queue: "queue.Queue[dict[str, Any]]" = queue.Queue(maxsize=self.config.queue_maxsize)
        self.transport = KafkaEventTransport(self.config, self.logger)
        self.collectors = [
            ProcessCollector(self.config, self.event_queue, self.logger, self.stop_event),
            NetworkCollector(self.config, self.event_queue, self.logger, self.stop_event),
        ]
        if self.config.os_family == "windows":
            self.collectors.append(WindowsEventCollector(self.config, self.event_queue, self.logger, self.stop_event))
            if self.config.enable_sysmon:
                self.collectors.append(SysmonCollector(self.config, self.event_queue, self.logger, self.stop_event))
            if self.config.enable_etw:
                self.collectors.append(ETWCollector(self.config, self.event_queue, self.logger, self.stop_event))
        else:
            if self.config.enable_linux_audit:
                self.collectors.append(LinuxAuditCollector(self.config, self.event_queue, self.logger, self.stop_event))
        self.publisher_thread = threading.Thread(target=self._publisher_loop, name="publisher-loop", daemon=True)
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, name="heartbeat-loop", daemon=True)

    def start(self) -> None:
        self.logger.info(
            "agent starting",
            extra={
                "payload": {
                    "host": self.config.hostname,
                    "machine_id": self.config.machine_id,
                    "topic": self.config.kafka_topic,
                    "tenant_id": self.config.tenant_id,
                }
            },
        )
        set_tenant_id(self.config.tenant_id)
        SERVICE_HEALTH.labels(service="windows-agent").set(1)
        for collector in self.collectors:
            collector.start()
        self.publisher_thread.start()
        self.heartbeat_thread.start()

    def run_forever(self) -> None:
        self.start()
        try:
            while not self.stop_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self) -> None:
        self.stop_event.set()
        SERVICE_HEALTH.labels(service="windows-agent").set(0)
        self.logger.info("agent stopping", extra={"payload": {"host": self.config.hostname}})

    def _publisher_loop(self) -> None:
        while not self.stop_event.is_set():
            set_correlation_id(None)
            batch = self._drain_queue()
            if batch:
                sent = self.transport.send_batch(batch)
                self.logger.info(
                    "batch published",
                    extra={"payload": {"batch_size": len(batch), "published": sent, "buffered": len(self.transport.offline_buffer)}},
                )
            self.stop_event.wait(self.config.batch_flush_seconds)

    def _heartbeat_loop(self) -> None:
        while not self.stop_event.is_set():
            queue_depth = self.event_queue.qsize()
            event = heartbeat_event(self.config, queue_depth=queue_depth)
            try:
                self.event_queue.put_nowait(event)
            except queue.Full:
                self.logger.warning("heartbeat dropped", extra={"payload": {"reason": "queue_full"}})
            self.control_plane.heartbeat(
                cpu_usage=self._cpu_usage(),
                memory_usage=self._memory_usage(),
                active_processes=self._active_process_count(),
                agent_health="healthy",
                queue_depth=queue_depth,
            )
            self.stop_event.wait(self.config.heartbeat_seconds)

    def _drain_queue(self) -> list[dict[str, Any]]:
        batch: list[dict[str, Any]] = []
        while True:
            try:
                batch.append(self.event_queue.get_nowait())
            except queue.Empty:
                break
        return batch

    @staticmethod
    def _cpu_usage() -> float:
        if psutil is None:
            return 0.0
        try:
            return float(psutil.cpu_percent(interval=None))
        except Exception:
            return 0.0

    @staticmethod
    def _memory_usage() -> float:
        if psutil is None:
            return 0.0
        try:
            return float(psutil.virtual_memory().percent)
        except Exception:
            return 0.0

    @staticmethod
    def _active_process_count() -> int:
        if psutil is None:
            return 0
        try:
            return len(psutil.pids())
        except Exception:
            return 0


def main() -> None:
    WindowsEDRAgent().run_forever()


if __name__ == "__main__":
    main()
