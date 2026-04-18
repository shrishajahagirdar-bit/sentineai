from __future__ import annotations

import platform
import socket
from datetime import datetime, timezone
from typing import Any

from collector.storage import load_json, save_json
from sentinel_config import CONFIG

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


KNOWN_SYSTEM_PROCESSES = {
    "system",
    "registry",
    "idle",
    "svchost.exe",
    "explorer.exe",
    "lsass.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
}


class ProcessCollector:
    def __init__(self) -> None:
        self.previous = load_json(CONFIG.process_state, {})
        self.hostname = socket.gethostname()

    def collect(self) -> list[dict[str, Any]]:
        if psutil is None:
            return []

        events: list[dict[str, Any]] = []
        current: dict[str, dict[str, Any]] = {}
        timestamp = datetime.now(timezone.utc).isoformat()

        for proc in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_info", "create_time", "exe"]):
            try:
                info = proc.info
                pid = str(info["pid"])
                current[pid] = {
                    "name": info.get("name") or "unknown",
                    "username": info.get("username") or "unknown",
                    "create_time": info.get("create_time") or 0,
                    "exe": info.get("exe") or "",
                }
                previous_proc = self.previous.get(pid)
                if pid not in self.previous or previous_proc != current[pid]:
                    events.append(
                        {
                            "timestamp": timestamp,
                            "hostname": self.hostname,
                            "source": "process",
                            "event_type": "process_start",
                            "status": "ok",
                            "pid": int(pid),
                            "process_name": current[pid]["name"],
                            "user": current[pid]["username"],
                            "cpu_percent": float(info.get("cpu_percent") or 0.0),
                            "memory_rss": int(getattr(info.get("memory_info"), "rss", 0)),
                            "exe": current[pid]["exe"],
                            "unknown_process": self._is_unknown_process(current[pid]["name"], current[pid]["exe"]),
                            "message": f"Process started: {current[pid]['name']}",
                            "raw_log": f"process_start pid={pid} name={current[pid]['name']} user={current[pid]['username']}",
                            "parsed_fields": {
                                "pid": int(pid),
                                "process_name": current[pid]["name"],
                                "username": current[pid]["username"],
                                "cpu_percent": float(info.get("cpu_percent") or 0.0),
                                "memory_rss": int(getattr(info.get("memory_info"), "rss", 0)),
                                "create_time": float(current[pid]["create_time"] or 0),
                                "exe": current[pid]["exe"],
                                "process_owner": current[pid]["username"],
                            },
                            "metadata": {
                                "collector": "psutil",
                                "platform": platform.system().lower(),
                            },
                        }
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        self.previous = current
        save_json(CONFIG.process_state, current)
        return events[: CONFIG.max_process_events_per_cycle]

    @staticmethod
    def _is_unknown_process(name: str, exe_path: str) -> bool:
        lower_name = (name or "").lower()
        lower_path = (exe_path or "").lower()
        if lower_name in KNOWN_SYSTEM_PROCESSES:
            return False
        return not (lower_path.startswith("c:\\windows") or lower_path.startswith("c:\\program files"))
