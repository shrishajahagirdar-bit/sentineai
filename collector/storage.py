from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.safe_wrapper import log_health_event, safe_execution
from sentinel_config import CONFIG


def ensure_storage() -> None:
    for path in [
        CONFIG.storage_dir / "events",
        CONFIG.storage_dir / "incidents",
        CONFIG.storage_dir / "models",
        CONFIG.storage_dir / "baselines",
        CONFIG.state_dir,
    ]:
        path.mkdir(parents=True, exist_ok=True)


@safe_execution(default_factory=lambda: {}, operation="collector_load_json")
def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        log_health_event("warning", "collector_load_json", "Invalid JSON encountered; default returned.", context={"path": str(path)})
        return default


def save_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


@safe_execution(default_factory=lambda: None, operation="collector_append_jsonl")
def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, default=str) + "\n")


@safe_execution(default_factory=list, operation="collector_read_jsonl")
def read_jsonl(path: Path, limit: int | None = None) -> list[dict[str, Any]]:
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
                log_health_event("warning", "collector_read_jsonl", "Malformed JSONL row skipped.", context={"path": str(path)})
                continue

    if limit is None:
        return records
    return records[-limit:]
