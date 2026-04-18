from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class JsonlSpool:
    def __init__(self, path: Path) -> None:
        self.path = path

    def append(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, default=str) + "\n")

    def drain(self, limit: int = 1000) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        records: list[dict[str, Any]] = []
        remaining: list[str] = []
        for idx, line in enumerate(lines):
            if idx < limit:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            else:
                remaining.append(line)
        self.path.write_text("\n".join(remaining) + ("\n" if remaining else ""), encoding="utf-8")
        return records
