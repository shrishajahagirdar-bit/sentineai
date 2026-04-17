from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta
from typing import Any


class RuleEngine:
    def __init__(self) -> None:
        self.failed_logins: dict[str, deque[datetime]] = {}

    def evaluate(self, event: dict[str, Any]) -> tuple[float, list[str]]:
        score = 0
        triggers: list[str] = []
        user = str(event.get("user", "unknown"))
        now = datetime.fromisoformat(str(event.get("timestamp")).replace("Z", "+00:00"))

        if event.get("event_type") == "login_failure":
            failures = self.failed_logins.setdefault(user, deque())
            failures.append(now)
            while failures and now - failures[0] > timedelta(minutes=15):
                failures.popleft()
            score += 20
            triggers.append("failed login attempts +20")

        if event.get("unknown_process"):
            score += 25
            triggers.append("unknown process +25")

        if event.get("unusual_network_ip"):
            score += 25
            triggers.append("unusual network IP +25")

        if event.get("sensitive_file_access"):
            score += 30
            triggers.append("sensitive file access +30")

        return min(score / 100.0, 1.0), triggers

