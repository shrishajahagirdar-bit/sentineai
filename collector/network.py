from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any

from collector.storage import load_json, save_json
from sentinel_config import CONFIG

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


class NetworkCollector:
    def __init__(self) -> None:
        self.previous = load_json(CONFIG.network_state, {})

    def collect(self) -> list[dict[str, Any]]:
        if psutil is None:
            return [self._status_event("warning", "psutil is not installed; network monitoring is unavailable.")]

        events: list[dict[str, Any]] = []
        current: dict[str, dict[str, Any]] = {}
        timestamp = datetime.now(timezone.utc).isoformat()

        try:
            connections = psutil.net_connections(kind="inet")
        except Exception as exc:
            return [self._status_event("warning", f"Unable to enumerate network connections: {exc}")]

        for conn in connections:
            try:
                laddr = getattr(conn, "laddr", None)
                raddr = getattr(conn, "raddr", None)
                if not laddr:
                    continue

                local_ip = getattr(laddr, "ip", "")
                local_port = int(getattr(laddr, "port", 0))
                remote_ip = getattr(raddr, "ip", "") if raddr else ""
                remote_port = int(getattr(raddr, "port", 0)) if raddr else 0
                identity = f"{conn.pid}:{local_ip}:{local_port}:{remote_ip}:{remote_port}:{conn.status}"
                current[identity] = {
                    "pid": conn.pid or 0,
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "status": conn.status,
                }

                if identity not in self.previous and remote_ip:
                    events.append(
                        {
                            "timestamp": timestamp,
                            "source": "network_monitor",
                            "event_type": "network_connection",
                            "status": "ok",
                            "pid": conn.pid or 0,
                            "local_ip": local_ip,
                            "local_port": local_port,
                            "remote_ip": remote_ip,
                            "remote_port": remote_port,
                            "connection_state": conn.status,
                            "user": "system",
                            "suspicious_port": remote_port in CONFIG.suspicious_ports or local_port in CONFIG.suspicious_ports,
                            "unusual_network_ip": self._is_unusual_ip(remote_ip),
                            "message": f"Connection observed to {remote_ip}:{remote_port}",
                        }
                    )
            except Exception:
                continue

        self.previous = current
        save_json(CONFIG.network_state, current)
        return events

    @staticmethod
    def _is_unusual_ip(value: str) -> bool:
        try:
            ip = ipaddress.ip_address(value)
            return not (ip.is_private or ip.is_loopback or ip.is_link_local)
        except ValueError:
            return False

    @staticmethod
    def _status_event(level: str, message: str) -> dict[str, Any]:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "network_monitor",
            "event_type": "collector_status",
            "status": level,
            "message": message,
            "user": "system",
        }

