from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


@dataclass(frozen=True)
class SentinelConfig:
    storage_dir: Path = BASE_DIR / "storage"
    event_store: Path = BASE_DIR / "storage" / "events" / "telemetry.jsonl"
    incident_store: Path = BASE_DIR / "storage" / "incidents" / "incidents.jsonl"
    feedback_store: Path = BASE_DIR / "storage" / "incidents" / "feedback.jsonl"
    baseline_store: Path = BASE_DIR / "storage" / "baselines" / "user_baselines.json"
    model_store: Path = BASE_DIR / "storage" / "models" / "sentinel_models.joblib"
    model_metadata_store: Path = BASE_DIR / "storage" / "models" / "model_metadata.json"
    state_dir: Path = BASE_DIR / "collector" / "state"
    event_log_state: Path = BASE_DIR / "collector" / "state" / "eventlog_offsets.json"
    process_state: Path = BASE_DIR / "collector" / "state" / "process_snapshot.json"
    network_state: Path = BASE_DIR / "collector" / "state" / "network_snapshot.json"
    monitor_directories: list[Path] = field(
        default_factory=lambda: [
            Path.home() / "Desktop",
            Path.home() / "Documents",
            Path.home() / "Downloads",
        ]
    )
    event_logs: list[str] = field(default_factory=lambda: ["Security", "System", "Application"])
    poll_interval_seconds: int = 10
    dashboard_refresh_ms: int = 5000
    max_events: int = 5000
    suspicious_ports: set[int] = field(default_factory=lambda: {21, 22, 23, 135, 445, 3389, 4444, 5985, 5986})
    sensitive_path_keywords: tuple[str, ...] = ("credential", "secret", "payroll", "finance", "hr", "confidential")


CONFIG = SentinelConfig()

