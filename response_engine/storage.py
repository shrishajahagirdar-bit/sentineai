from __future__ import annotations

import json
from pathlib import Path
from typing import Any


AUDIT_PATH = Path(__file__).resolve().parents[1] / "storage" / "response" / "audit.jsonl"


def append_audit(payload: dict[str, Any]) -> None:
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, default=str) + "\n")
