from __future__ import annotations

import hashlib
from typing import Any

import pandas as pd


def stable_bucket(value: str | None, modulus: int = 1024) -> int:
    raw = (value or "unknown").encode("utf-8", errors="ignore")
    return int(hashlib.sha256(raw).hexdigest(), 16) % modulus


def event_to_feature_row(event: dict[str, Any]) -> dict[str, Any]:
    event_type = str(event.get("event_type", "unknown"))
    source = str(event.get("source", "unknown"))
    user = str(event.get("user", "unknown"))
    process_name = str(event.get("process_name", "unknown"))
    remote_ip = str(event.get("remote_ip", ""))
    path = str(event.get("path", ""))

    timestamp = pd.to_datetime(event.get("timestamp"), errors="coerce")
    hour = int(timestamp.hour) if not pd.isna(timestamp) else 0

    return {
        "event_type_bucket": stable_bucket(event_type),
        "source_bucket": stable_bucket(source),
        "user_bucket": stable_bucket(user),
        "process_bucket": stable_bucket(process_name),
        "remote_ip_bucket": stable_bucket(remote_ip),
        "path_bucket": stable_bucket(path),
        "hour": hour,
        "failed_login_flag": 1 if event_type == "login_failure" else 0,
        "privileged_logon_flag": 1 if event_type == "privileged_logon" else 0,
        "unknown_process_flag": int(bool(event.get("unknown_process"))),
        "unusual_network_ip_flag": int(bool(event.get("unusual_network_ip"))),
        "suspicious_port_flag": int(bool(event.get("suspicious_port"))),
        "sensitive_file_flag": int(bool(event.get("sensitive_file_access"))),
        "cpu_percent": float(event.get("cpu_percent") or 0.0),
        "memory_rss": float(event.get("memory_rss") or 0.0),
        "local_port": float(event.get("local_port") or 0.0),
        "remote_port": float(event.get("remote_port") or 0.0),
    }


def events_to_frame(events: list[dict[str, Any]]) -> pd.DataFrame:
    rows = [event_to_feature_row(event) for event in events]
    if not rows:
        return pd.DataFrame(columns=list(event_to_feature_row({}).keys()))
    return pd.DataFrame(rows)

