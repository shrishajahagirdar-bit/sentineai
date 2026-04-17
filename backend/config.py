from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Settings:
    app_name: str = "SentinelAI"
    api_prefix: str = ""
    processed_dir: Path = ROOT_DIR / "data_pipeline" / "processed"
    datasets_dir: Path = ROOT_DIR / "datasets"
    artifacts_dir: Path = ROOT_DIR / "ml" / "artifacts"
    feedback_file: Path = ROOT_DIR / "storage" / "feedback" / "feedback.jsonl"
    profile_file: Path = ROOT_DIR / "storage" / "profiles" / "user_profiles.json"
    timeline_file: Path = ROOT_DIR / "storage" / "timelines" / "incident_history.jsonl"
    network_export: Path = ROOT_DIR / "data_pipeline" / "processed" / "network_events.csv"
    auth_export: Path = ROOT_DIR / "data_pipeline" / "processed" / "auth_events.csv"
    metrics_file: Path = ROOT_DIR / "ml" / "artifacts" / "metrics.json"
    risk_export: Path = ROOT_DIR / "data_pipeline" / "processed" / "risk_feed.csv"


settings = Settings()

