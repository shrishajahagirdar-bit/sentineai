from __future__ import annotations

import socket
from datetime import datetime, timezone
from typing import Any

from collector.storage import load_json, save_json
from sentinel_config import CONFIG

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


class SessionCollector:
    def __init__(self) -> None:
        self.previous = load_json(CONFIG.session_state, {})
        self.hostname = socket.gethostname()

    def collect(self) -> list[dict[str, Any]]:
        if psutil is None:
            return []

        current: dict[str, dict[str, Any]] = {}
        events: list[dict[str, Any]] = []
        now = datetime.now(timezone.utc).isoformat()

        try:
            sessions = psutil.users()
        except Exception:
            sessions = []

        for session in sessions:
            user = str(getattr(session, "name", "") or "unknown")
            terminal = str(getattr(session, "terminal", "") or "unknown")
            host = str(getattr(session, "host", "") or "")
            started = float(getattr(session, "started", 0.0) or 0.0)
            identity = f"{user}|{terminal}|{host}|{started}"
            current[identity] = {
                "user": user,
                "terminal": terminal,
                "remote_host": host,
                "started": started,
            }
            if identity not in self.previous:
                events.append(
                    {
                        "timestamp": now,
                        "hostname": self.hostname,
                        "source": "auth",
                        "event_type": "session_login",
                        "severity": "low",
                        "status": "ok",
                        "user": user,
                        "raw_log": f"session_login user={user} terminal={terminal} remote_host={host}",
                        "message": f"User session observed for {user}",
                        "parsed_fields": current[identity],
                        "metadata": {"collector": "psutil.users"},
                    }
                )

        for identity, prior in self.previous.items():
            if identity not in current:
                events.append(
                    {
                        "timestamp": now,
                        "hostname": self.hostname,
                        "source": "auth",
                        "event_type": "session_logout",
                        "severity": "low",
                        "status": "ok",
                        "user": str(prior.get("user", "unknown")),
                        "raw_log": (
                            f"session_logout user={prior.get('user', 'unknown')} "
                            f"terminal={prior.get('terminal', 'unknown')} remote_host={prior.get('remote_host', '')}"
                        ),
                        "message": f"User session ended for {prior.get('user', 'unknown')}",
                        "parsed_fields": prior,
                        "metadata": {"collector": "psutil.users"},
                    }
                )

        self.previous = current
        save_json(CONFIG.session_state, current)
        return events
