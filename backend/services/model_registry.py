from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib

from backend.config import settings


class ModelRegistry:
    def __init__(self) -> None:
        self.supervised_path = settings.artifacts_dir / "supervised_pipeline.joblib"
        self.unsupervised_path = settings.artifacts_dir / "unsupervised_pipeline.joblib"
        self.metrics_path = settings.metrics_file

        self.supervised = self._load_joblib(self.supervised_path)
        self.unsupervised = self._load_joblib(self.unsupervised_path)
        self.metrics = self._load_metrics(self.metrics_path)

    @staticmethod
    def _load_joblib(path: Path) -> Any | None:
        if not path.exists():
            return None
        return joblib.load(path)

    @staticmethod
    def _load_metrics(path: Path) -> dict[str, Any]:
        if not path.exists():
            return {}
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    @property
    def ready(self) -> bool:
        return self.supervised is not None and self.unsupervised is not None

