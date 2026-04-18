from __future__ import annotations

import hashlib
from typing import Any

import numpy as np
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
    parsed_fields = event.get("parsed_fields", {})
    metadata = event.get("metadata", {})
    if not isinstance(parsed_fields, dict):
        parsed_fields = {}
    if not isinstance(metadata, dict):
        metadata = {}

    timestamp = pd.to_datetime(event.get("timestamp"), errors="coerce")
    hour = int(timestamp.hour) if not pd.isna(timestamp) else 0
    severity = str(event.get("severity", "low")).lower()
    severity_map = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}

    return {
        "event_type_bucket": stable_bucket(event_type),
        "source_bucket": stable_bucket(source),
        "user_bucket": stable_bucket(user),
        "process_bucket": stable_bucket(process_name),
        "remote_ip_bucket": stable_bucket(remote_ip),
        "path_bucket": stable_bucket(path),
        "attack_type_bucket": stable_bucket(str(event.get("attack_type", metadata.get("attack_type", "none")))),
        "hour": hour,
        "severity_score": severity_map.get(severity, 0.0),
        "failed_login_flag": 1 if event_type == "login_failure" else 0,
        "privileged_logon_flag": 1 if event_type == "privileged_logon" else 0,
        "anomaly_event_flag": 1 if event_type == "anomaly" else 0,
        "unknown_process_flag": int(bool(event.get("unknown_process"))),
        "unusual_network_ip_flag": int(bool(event.get("unusual_network_ip"))),
        "suspicious_port_flag": int(bool(event.get("suspicious_port"))),
        "sensitive_file_flag": int(bool(event.get("sensitive_file_access"))),
        "cpu_percent": float(event.get("cpu_percent", parsed_fields.get("cpu_percent", 0.0)) or 0.0),
        "memory_rss": float(event.get("memory_rss", parsed_fields.get("memory_rss", 0.0)) or 0.0),
        "local_port": float(event.get("local_port", parsed_fields.get("local_port", 0.0)) or 0.0),
        "remote_port": float(event.get("remote_port", parsed_fields.get("remote_port", 0.0)) or 0.0),
        "login_failure_count": float(parsed_fields.get("login_failure_count", 0.0) or 0.0),
        "packet_rate": float(parsed_fields.get("packet_rate", 0.0) or 0.0),
        "bandwidth_usage": float(parsed_fields.get("bandwidth_usage", 0.0) or 0.0),
        "access_time_anomaly": float(bool(parsed_fields.get("access_time_anomaly"))),
        "privilege_level_change": float(bool(parsed_fields.get("privilege_level_change"))),
        "risk_score": float(event.get("risk_score", event.get("ml_score", 0.0)) or 0.0),
    }


def events_to_frame(events: list[dict[str, Any]]) -> pd.DataFrame:
    rows = [event_to_feature_row(event) for event in events]
    if not rows:
        return pd.DataFrame(columns=list(event_to_feature_row({}).keys()))
    frame = pd.DataFrame(rows)
    numeric_frame = frame.apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], 0.0).fillna(0.0)
    return numeric_frame
