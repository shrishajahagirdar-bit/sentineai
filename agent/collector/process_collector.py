from __future__ import annotations

import json
import queue
import threading
import time
from typing import Any

from agent.core.config import AgentConfig
from agent.core.normalizer import build_event

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


class ProcessCollector(threading.Thread):
    def __init__(
        self,
        config: AgentConfig,
        output_queue: "queue.Queue[dict[str, Any]]",
        logger: Any,
        stop_event: threading.Event,
    ) -> None:
        super().__init__(name="process-collector", daemon=True)
        self.config = config
        self.output_queue = output_queue
        self.logger = logger
        self.stop_event = stop_event
        self.previous = self._load_snapshot()

    def run(self) -> None:
        while not self.stop_event.is_set():
            self._collect_cycle()
            self.stop_event.wait(self.config.process_poll_seconds)

    def _collect_cycle(self) -> None:
        if psutil is None:
            return

        current: dict[str, dict[str, Any]] = {}
        for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info", "username", "create_time", "ppid"]):
            try:
                info = proc.info
                pid = str(info.get("pid") or 0)
                current[pid] = {
                    "process_name": info.get("name") or "unknown",
                    "cpu": float(info.get("cpu_percent") or 0.0),
                    "memory": int(getattr(info.get("memory_info"), "rss", 0) or 0),
                    "user": info.get("username") or "unknown",
                    "creation_time": float(info.get("create_time") or 0.0),
                    "parent_pid": int(info.get("ppid") or 0),
                }
                if pid not in self.previous:
                    self._enqueue_event(pid, current[pid])
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as exc:
                self.logger.warning("process collection warning", extra={"payload": {"error": str(exc), "collector": "process"}})

        self.previous = current
        self._save_snapshot(current)

    def _enqueue_event(self, pid: str, payload: dict[str, Any]) -> None:
        event = build_event(
            self.config,
            user=str(payload.get("user", "unknown")),
            event_source="process",
            event_type="process_create",
            severity="low",
            raw_data={
                "creation_time": payload.get("creation_time", 0.0),
                "parent_pid": payload.get("parent_pid", 0),
            },
            process_name=str(payload.get("process_name", "")),
            pid=int(pid),
            cpu=float(payload.get("cpu", 0.0)),
            memory=int(payload.get("memory", 0)),
        )
        self._put(event)

    def _put(self, event: dict[str, Any]) -> None:
        try:
            self.output_queue.put_nowait(event)
        except queue.Full:
            self.logger.warning("agent queue full", extra={"payload": {"collector": "process", "event_type": event.get("event_type")}})

    def _load_snapshot(self) -> dict[str, dict[str, Any]]:
        try:
            if self.config.process_state_path.exists():
                return json.loads(self.config.process_state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
        return {}

    def _save_snapshot(self, snapshot: dict[str, dict[str, Any]]) -> None:
        try:
            self.config.process_state_path.parent.mkdir(parents=True, exist_ok=True)
            self.config.process_state_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
        except OSError:
            return
