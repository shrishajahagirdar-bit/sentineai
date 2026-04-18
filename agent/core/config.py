from __future__ import annotations

import os
import platform
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4


BASE_DIR = Path(__file__).resolve().parents[2]
AGENT_DIR = BASE_DIR / "agent"


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _resolve_session_name() -> str:
    session_name = os.getenv("SESSIONNAME")
    if session_name:
        return session_name

    try:
        result = subprocess.run(
            ["query", "session"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except Exception:
        return "unknown"

    if result.returncode != 0:
        return "unknown"

    for line in result.stdout.splitlines():
        if "console" in line.lower():
            return "console"
    return "unknown"


def _load_or_create_machine_id(path: Path) -> str:
    try:
        if path.exists():
            value = path.read_text(encoding="utf-8").strip()
            if value:
                return value
        path.parent.mkdir(parents=True, exist_ok=True)
        machine_id = str(uuid4())
        path.write_text(machine_id, encoding="utf-8")
        return machine_id
    except OSError:
        return str(uuid4())


@dataclass(frozen=True)
class AgentConfig:
    agent_name: str
    hostname: str
    session_name: str
    machine_id: str
    state_dir: Path
    log_dir: Path
    log_path: Path
    machine_id_path: Path
    enrollment_state_path: Path
    enrollment_token_path: Path
    spool_path: Path
    process_state_path: Path
    network_state_path: Path
    event_state_path: Path
    control_plane_url: str | None
    tenant_id: str | None
    agent_id: str | None
    kafka_bootstrap_servers: list[str]
    kafka_topic: str
    backend_http_url: str | None
    process_poll_seconds: float
    network_poll_seconds: float
    event_poll_seconds: float
    batch_flush_seconds: float
    heartbeat_seconds: float
    queue_maxsize: int
    publisher_retries: int
    publisher_retry_backoff_seconds: float
    enable_sysmon: bool
    enable_etw: bool
    enable_linux_audit: bool
    os_family: str

    @classmethod
    def load(cls) -> "AgentConfig":
        state_dir = AGENT_DIR / "state"
        log_dir = BASE_DIR / "logs"
        machine_id_path = state_dir / "machine_id.txt"
        bootstrap = os.getenv("SENTINEL_AGENT_KAFKA_BOOTSTRAP", "localhost:9092")
        kafka_bootstrap_servers = [item.strip() for item in bootstrap.split(",") if item.strip()]

        return cls(
            agent_name="SentinelAI Windows Agent",
            hostname=socket.gethostname(),
            session_name=_resolve_session_name(),
            machine_id=_load_or_create_machine_id(machine_id_path),
            state_dir=state_dir,
            log_dir=log_dir,
            log_path=log_dir / "agent.log",
            machine_id_path=machine_id_path,
            enrollment_state_path=state_dir / "enrollment.json",
            enrollment_token_path=state_dir / "enrollment_token.txt",
            spool_path=state_dir / "event_spool.jsonl",
            process_state_path=state_dir / "process_snapshot.json",
            network_state_path=state_dir / "network_snapshot.json",
            event_state_path=state_dir / "event_offsets.json",
            control_plane_url=os.getenv("SENTINEL_AGENT_CONTROL_PLANE_URL", "http://localhost:8010"),
            tenant_id=None,
            agent_id=None,
            kafka_bootstrap_servers=kafka_bootstrap_servers or ["localhost:9092"],
            kafka_topic=os.getenv("SENTINEL_AGENT_KAFKA_TOPIC", "tenant-events"),
            backend_http_url=os.getenv("SENTINEL_AGENT_HTTP_URL"),
            process_poll_seconds=_env_float("SENTINEL_AGENT_PROCESS_POLL_SECONDS", 2.0),
            network_poll_seconds=_env_float("SENTINEL_AGENT_NETWORK_POLL_SECONDS", 2.0),
            event_poll_seconds=_env_float("SENTINEL_AGENT_EVENT_POLL_SECONDS", 2.0),
            batch_flush_seconds=_env_float("SENTINEL_AGENT_BATCH_FLUSH_SECONDS", 1.0),
            heartbeat_seconds=_env_float("SENTINEL_AGENT_HEARTBEAT_SECONDS", 10.0),
            queue_maxsize=_env_int("SENTINEL_AGENT_QUEUE_MAXSIZE", 5000),
            publisher_retries=_env_int("SENTINEL_AGENT_PUBLISHER_RETRIES", 3),
            publisher_retry_backoff_seconds=_env_float("SENTINEL_AGENT_RETRY_BACKOFF_SECONDS", 1.0),
            enable_sysmon=os.getenv("SENTINEL_AGENT_ENABLE_SYSMON", "true").lower() not in {"0", "false", "no"},
            enable_etw=os.getenv("SENTINEL_AGENT_ENABLE_ETW", "false").lower() in {"1", "true", "yes"},
            enable_linux_audit=os.getenv("SENTINEL_AGENT_ENABLE_LINUX_AUDIT", "true").lower() not in {"0", "false", "no"},
            os_family=platform.system().lower(),
        )

    def ensure_directories(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
