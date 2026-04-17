from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

import pandas as pd

from collector.storage import load_json, read_jsonl, save_json
from sentinel_config import CONFIG


class UebaEngine:
    def __init__(self) -> None:
        self.baselines = load_json(CONFIG.baseline_store, {})

    def rebuild(self, events: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        source_events = events if events is not None else read_jsonl(CONFIG.event_store, limit=None)
        baselines: dict[str, Any] = {}

        for event in source_events:
            user = str(event.get("user", "unknown"))
            if user == "unknown":
                continue

            profile = baselines.setdefault(
                user,
                {
                    "login_hours": Counter(),
                    "processes": Counter(),
                    "paths": Counter(),
                    "remote_ips": Counter(),
                },
            )

            timestamp = pd.to_datetime(event.get("timestamp"), errors="coerce")
            if not pd.isna(timestamp):
                profile["login_hours"][str(int(timestamp.hour))] += 1
            if event.get("process_name"):
                profile["processes"][str(event["process_name"]).lower()] += 1
            if event.get("path"):
                profile["paths"][str(event["path"]).lower()] += 1
            if event.get("remote_ip"):
                profile["remote_ips"][str(event["remote_ip"])] += 1

        normalized: dict[str, Any] = {}
        for user, profile in baselines.items():
            hours_total = max(sum(profile["login_hours"].values()), 1)
            normalized[user] = {
                "login_time_patterns": {hour: round(count / hours_total, 4) for hour, count in profile["login_hours"].items()},
                "process_usage_patterns": profile["processes"].most_common(15),
                "file_access_patterns": profile["paths"].most_common(15),
                "network_behavior_patterns": profile["remote_ips"].most_common(15),
                "updated_at": datetime.utcnow().isoformat(),
            }

        self.baselines = normalized
        save_json(CONFIG.baseline_store, normalized)
        return normalized

    def score(self, event: dict[str, Any]) -> tuple[float, list[str]]:
        user = str(event.get("user", "unknown"))
        baseline = self.baselines.get(user)
        if not baseline:
            return 0.15, ["new user baseline"]

        reasons: list[str] = []
        deviation = 0.0

        timestamp = pd.to_datetime(event.get("timestamp"), errors="coerce")
        if not pd.isna(timestamp):
            hour_probability = baseline["login_time_patterns"].get(str(int(timestamp.hour)), 0.0)
            if hour_probability < 0.05:
                deviation += 0.20
                reasons.append("unusual login time")

        process_name = str(event.get("process_name", "")).lower()
        common_processes = {name for name, _ in baseline["process_usage_patterns"]}
        if process_name and process_name not in common_processes:
            deviation += 0.20
            reasons.append("unusual process usage")

        path = str(event.get("path", "")).lower()
        common_paths = {name for name, _ in baseline["file_access_patterns"]}
        if path and common_paths and path not in common_paths:
            deviation += 0.20
            reasons.append("unusual file access")

        remote_ip = str(event.get("remote_ip", ""))
        common_ips = {name for name, _ in baseline["network_behavior_patterns"]}
        if remote_ip and common_ips and remote_ip not in common_ips:
            deviation += 0.20
            reasons.append("unusual network destination")

        return min(deviation, 1.0), reasons

