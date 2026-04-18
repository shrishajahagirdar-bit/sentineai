from __future__ import annotations

import json
import queue
import threading
from typing import Any

from agent.core.config import AgentConfig
from agent.core.normalizer import build_event

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


class NetworkCollector(threading.Thread):
    def __init__(
        self,
        config: AgentConfig,
        output_queue: "queue.Queue[dict[str, Any]]",
        logger: Any,
        stop_event: threading.Event,
    ) -> None:
        super().__init__(name="network-collector", daemon=True)
        self.config = config
        self.output_queue = output_queue
        self.logger = logger
        self.stop_event = stop_event
        self.previous = self._load_snapshot()

    def run(self) -> None:
        while not self.stop_event.is_set():
            self._collect_cycle()
            self.stop_event.wait(self.config.network_poll_seconds)

    def _collect_cycle(self) -> None:
        if psutil is None:
            return

        current: dict[str, dict[str, Any]] = {}
        try:
            connections = psutil.net_connections(kind="inet")
        except Exception as exc:
            self.logger.warning("network collection warning", extra={"payload": {"error": str(exc), "collector": "network"}})
            return

        for conn in connections:
            laddr = getattr(conn, "laddr", None)
            raddr = getattr(conn, "raddr", None)
            if not laddr:
                continue

            local_ip = getattr(laddr, "ip", "")
            local_port = int(getattr(laddr, "port", 0) or 0)
            remote_ip = getattr(raddr, "ip", "") if raddr else ""
            remote_port = int(getattr(raddr, "port", 0) or 0) if raddr else 0
            pid = int(getattr(conn, "pid", 0) or 0)
            key = f"{pid}:{local_ip}:{local_port}:{remote_ip}:{remote_port}:{conn.status}"
            current[key] = {
                "pid": pid,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "status": str(conn.status),
            }
            if key not in self.previous and remote_ip:
                self._enqueue_event(current[key])

        self.previous = current
        self._save_snapshot(current)

    def _enqueue_event(self, payload: dict[str, Any]) -> None:
        process_name = ""
        user = "unknown"
        if psutil is not None and payload.get("pid"):
            try:
                proc = psutil.Process(int(payload["pid"]))
                process_name = proc.name()
                user = proc.username() or "unknown"
            except Exception:
                process_name = ""
                user = "unknown"

        event = build_event(
            self.config,
            user=user,
            event_source="network",
            event_type="network_connection",
            severity="medium" if payload.get("remote_ip") else "low",
            raw_data={"connection_status": payload.get("status", "")},
            process_name=process_name,
            pid=int(payload.get("pid", 0) or 0),
            network={
                "local_ip": payload.get("local_ip", ""),
                "remote_ip": payload.get("remote_ip", ""),
                "remote_port": int(payload.get("remote_port", 0) or 0),
                "local_port": int(payload.get("local_port", 0) or 0),
                "connection_status": payload.get("status", ""),
                "associated_process_pid": int(payload.get("pid", 0) or 0),
            },
        )
        self._put(event)

    def _put(self, event: dict[str, Any]) -> None:
        try:
            self.output_queue.put_nowait(event)
        except queue.Full:
            self.logger.warning("agent queue full", extra={"payload": {"collector": "network", "event_type": event.get("event_type")}})

    def _load_snapshot(self) -> dict[str, dict[str, Any]]:
        try:
            if self.config.network_state_path.exists():
                return json.loads(self.config.network_state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
        return {}

    def _save_snapshot(self, snapshot: dict[str, dict[str, Any]]) -> None:
        try:
            self.config.network_state_path.parent.mkdir(parents=True, exist_ok=True)
            self.config.network_state_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
        except OSError:
            return
