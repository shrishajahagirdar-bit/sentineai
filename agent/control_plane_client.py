from __future__ import annotations

import json
import hashlib
import hmac
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import requests

from agent.core.config import AgentConfig


class ControlPlaneClient:
    def __init__(self, config: AgentConfig, logger: Any) -> None:
        self.config = config
        self.logger = logger

    def enroll(self) -> AgentConfig:
        state = self._load_state()
        if state is not None:
            return replace(
                self.config,
                agent_id=state.get("agent_id"),
                tenant_id=state.get("tenant_id"),
                kafka_topic=state.get("kafka_topic", self.config.kafka_topic),
            )

        token = self._load_enrollment_token()
        if not token or not self.config.control_plane_url:
            return self.config

        try:
            response = requests.post(
                f"{self.config.control_plane_url.rstrip('/')}/agents/enroll",
                json={
                    "enrollment_token": token,
                    "hostname": self.config.hostname,
                    "os": "windows",
                    "agent_version": "0.1.0",
                    "machine_id": self.config.machine_id,
                },
                timeout=5,
            )
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:
            self.logger.warning("agent enrollment failed", extra={"payload": {"error": str(exc)}})
            return self.config

        self._save_state(payload)
        return replace(
            self.config,
            agent_id=payload.get("agent_id"),
            tenant_id=payload.get("tenant_id"),
            kafka_topic=payload.get("kafka_topic", self.config.kafka_topic),
        )

    def heartbeat(self, *, cpu_usage: float, memory_usage: float, active_processes: int, agent_health: str, queue_depth: int) -> None:
        if not self.config.control_plane_url or not self.config.agent_id:
            return
        timestamp = int(time.time())
        nonce = self.config.machine_id
        signature = hmac.new(
            key=(self.config.machine_id or "sentinelai").encode("utf-8"),
            msg=f"{self.config.agent_id}:{timestamp}:{nonce}".encode("utf-8"),
            digestmod=hashlib.sha256,
        ).hexdigest()
        try:
            requests.post(
                f"{self.config.control_plane_url.rstrip('/')}/agents/{self.config.agent_id}/heartbeat",
                json={
                    "cpu_usage": cpu_usage,
                    "memory_usage": memory_usage,
                    "active_processes": active_processes,
                    "agent_health": agent_health,
                    "queue_depth": queue_depth,
                },
                headers={
                    "x-agent-timestamp": str(timestamp),
                    "x-agent-nonce": nonce,
                    "x-agent-signature": signature,
                },
                timeout=5,
            ).raise_for_status()
        except Exception as exc:
            self.logger.warning("agent heartbeat failed", extra={"payload": {"error": str(exc)}})

    def _load_enrollment_token(self) -> str | None:
        try:
            if self.config.enrollment_token_path.exists():
                value = self.config.enrollment_token_path.read_text(encoding="utf-8").strip()
                return value or None
        except OSError:
            return None
        return None

    def _load_state(self) -> dict[str, Any] | None:
        try:
            if self.config.enrollment_state_path.exists():
                payload = json.loads(self.config.enrollment_state_path.read_text(encoding="utf-8"))
                if isinstance(payload, dict):
                    return payload
        except (OSError, json.JSONDecodeError):
            return None
        return None

    def _save_state(self, payload: dict[str, Any]) -> None:
        try:
            self.config.enrollment_state_path.parent.mkdir(parents=True, exist_ok=True)
            self.config.enrollment_state_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except OSError:
            return
