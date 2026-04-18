from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import platform


BASE_DIR = Path(__file__).resolve().parent


@dataclass(frozen=True)
class SentinelConfig:
    storage_dir: Path = BASE_DIR / "storage"
    event_store: Path = BASE_DIR / "storage" / "events" / "telemetry.jsonl"
    auth_event_store: Path = BASE_DIR / "storage" / "events" / "auth_events.jsonl"
    incident_store: Path = BASE_DIR / "storage" / "incidents" / "incidents.jsonl"
    alert_store: Path = BASE_DIR / "storage" / "alerts" / "alerts.jsonl"
    alert_dlq_store: Path = BASE_DIR / "storage" / "alerts" / "alerts_dlq.jsonl"
    kill_switch_store: Path = BASE_DIR / "storage" / "alerts" / "kill_switch_actions.jsonl"
    incident_case_store: Path = BASE_DIR / "storage" / "incidents" / "incident_cases.jsonl"
    feedback_store: Path = BASE_DIR / "storage" / "incidents" / "feedback.jsonl"
    dead_letter_store: Path = BASE_DIR / "storage" / "events" / "dead_letter.jsonl"
    baseline_store: Path = BASE_DIR / "storage" / "baselines" / "user_baselines.json"
    model_store: Path = BASE_DIR / "storage" / "models" / "sentinel_models.joblib"
    model_metadata_store: Path = BASE_DIR / "storage" / "models" / "model_metadata.json"
    state_dir: Path = BASE_DIR / "collector" / "state"
    event_log_state: Path = BASE_DIR / "collector" / "state" / "eventlog_offsets.json"
    process_state: Path = BASE_DIR / "collector" / "state" / "process_snapshot.json"
    network_state: Path = BASE_DIR / "collector" / "state" / "network_snapshot.json"
    session_state: Path = BASE_DIR / "collector" / "state" / "session_snapshot.json"
    linux_log_state: Path = BASE_DIR / "collector" / "state" / "linux_log_offsets.json"
    monitor_directories: list[Path] = field(
        default_factory=lambda: [
            Path.home() / "Desktop",
            Path.home() / "Documents",
            Path.home() / "Downloads",
        ]
    )
    event_logs: list[str] = field(default_factory=lambda: ["Security", "System", "Application"])
    sysmon_log_name: str = "Microsoft-Windows-Sysmon/Operational"
    poll_interval_seconds: int = 10
    dashboard_refresh_ms: int = 30000  # Increased from 5000ms (5s) to 30000ms (30s) to prevent flickering
    max_events: int = 5000
    incident_window_minutes: int = 10
    kafka_bootstrap_servers: list[str] = field(default_factory=lambda: ["localhost:9092"])
    kafka_topic: str = "security-logs"
    kafka_tenant_topic: str = "tenant-events"
    websocket_server_url: str = "ws://localhost:8001/ws/events"
    kafka_normalized_topic: str = "normalized-events"
    kafka_scored_topic: str = "scored-events"
    kafka_alerts_topic: str = "alerts"
    kafka_response_topic: str = "response-actions"
    kafka_dlq_topic: str = "security-logs-dlq"
    kafka_consumer_group: str = "sentinelai-consumers"
    kafka_retries: int = 3
    kafka_poll_timeout_seconds: float = 1.0
    kafka_use_real_broker: bool = True
    smtp_server: str = "localhost"
    smtp_port: int = 1025
    smtp_use_tls: bool = False
    smtp_username: str | None = None
    smtp_password: str | None = None
    alert_from_address: str = "alerts@sentinelai.local"
    dashboard_base_url: str = "http://localhost:8000"
    random_seed: int = 42
    suspicious_ports: set[int] = field(default_factory=lambda: {21, 22, 23, 135, 445, 3389, 4444, 5985, 5986})
    sensitive_path_keywords: tuple[str, ...] = ("credential", "secret", "payroll", "finance", "hr", "confidential")
    enable_file_monitor: bool = False
    enable_sysmon: bool = True
    max_eventlog_records_per_cycle: int = 256
    max_process_events_per_cycle: int = 256
    max_network_events_per_cycle: int = 256
    linux_auth_log: Path = Path("/var/log/auth.log")
    linux_syslog: Path = Path("/var/log/syslog")
    linux_secure_log: Path = Path("/var/log/secure")
    linux_journalctl_lines: int = 200
    os_platform: str = field(default_factory=lambda: platform.system().lower())


CONFIG = SentinelConfig()
