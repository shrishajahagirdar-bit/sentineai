from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd

from backend.config import settings
from core.safe_wrapper import log_health_event, safe_execution
from core.transformers import dataframe_to_records, normalize_event


@safe_execution(default_factory=pd.DataFrame, operation="backend_safe_read_csv")
def _safe_read_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame()
    try:
        return pd.read_csv(path)
    except Exception as exc:
        log_health_event(
            "error",
            "backend_safe_read_csv",
            "CSV load failed; empty frame returned.",
            context={"path": str(path), "error": str(exc)},
        )
        return pd.DataFrame()


def load_network_events(limit: int = 500) -> pd.DataFrame:
    df = _safe_read_csv(settings.network_export)
    if df.empty:
        return df
    return df.tail(limit).copy()


def load_auth_events(limit: int = 500) -> pd.DataFrame:
    df = _safe_read_csv(settings.auth_export)
    if df.empty:
        return df
    return df.tail(limit).copy()


@safe_execution(default_factory=dict, operation="backend_load_profiles")
def load_profiles() -> dict[str, Any]:
    if not settings.profile_file.exists():
        return {}
    try:
        with settings.profile_file.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        log_health_event(
            "error",
            "backend_load_profiles",
            "Profile store is invalid; returning empty profiles.",
            context={"error": str(exc)},
        )
        return {}
    return payload if isinstance(payload, dict) else {}


@safe_execution(default_factory=lambda: None, operation="backend_append_jsonl")
def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, default=str) + "\n")


@safe_execution(default_factory=list, operation="backend_load_jsonl")
def load_jsonl(path: Path, limit: int = 200) -> list[dict[str, Any]]:
    if not path.exists():
        return []

    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                log_health_event("warning", "backend_load_jsonl", "Malformed JSONL row skipped.", context={"path": str(path)})
    return records[-limit:]


def load_jsonl_events(path: Path, limit: int = 200) -> list[dict[str, Any]]:
    return [normalize_event(record) for record in load_jsonl(path, limit=limit)]


def dataframe_records(frame: Any) -> list[dict[str, Any]]:
    return dataframe_to_records(frame)
