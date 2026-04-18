from __future__ import annotations

import json
import logging
import smtplib
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any
from uuid import uuid4

try:
    from confluent_kafka import Consumer as ConfluentConsumer
except ImportError:  # pragma: no cover
    ConfluentConsumer = None

from backend.models.schemas import AlertPayload, AlertTestRequest, KillSwitchApproveRequest
from backend.services.data_access import append_jsonl, load_jsonl
from core.safe_wrapper import log_health_event
from core.transformers import normalize_event
from sentinel_config import CONFIG

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TenantDispatchConfig:
    tenant_id: str
    slack_webhook: str | None = None
    email_recipients: list[str] = field(default_factory=list)
    auto_response_allowed: bool = False
    allowlist_actions: tuple[str, ...] = field(default_factory=lambda: ("kill_process", "isolate_host", "block_ip"))
    dashboard_url: str = "http://localhost:8000"


DEFAULT_TENANT_CONFIGS: dict[str, TenantDispatchConfig] = {
    "default": TenantDispatchConfig(
        tenant_id="default",
        slack_webhook=None,
        email_recipients=["security@sentinelai.local"],
        auto_response_allowed=False,
        dashboard_url="http://localhost:8000/dashboard",
    )
}


def _retry(operation: Any, attempts: int = 3, base_delay: float = 0.1, factor: float = 2.0) -> Any:
    last_exc: Exception | None = None
    for attempt in range(attempts):
        try:
            return operation()
        except Exception as exc:
            last_exc = exc
            delay = min(base_delay * (factor ** attempt), 5.0)
            logger.warning("Retry %d/%d failed: %s", attempt + 1, attempts, exc)
            time.sleep(delay)
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("Retry operation failed without exception")


class SlackNotifier:
    def send_slack_alert(self, alert: AlertPayload, webhook_url: str) -> bool:
        if not webhook_url:
            raise ValueError("Tenant does not have a Slack webhook configured.")

        payload = {
            "text": f"🚨 SentinelAI ALERT: {alert.severity.upper()} for {alert.host or alert.user}",
            "attachments": [
                {
                    "color": self._slack_color(alert.severity),
                    "title": f"{alert.severity.upper()} Alert ({alert.event_type})",
                    "text": alert.description,
                    "fields": [
                        {"title": "Risk Score", "value": f"{alert.risk_score:.2f}", "short": True},
                        {"title": "Tenant", "value": alert.tenant_id, "short": True},
                        {"title": "Action", "value": alert.recommended_action, "short": True},
                        {"title": "Timestamp", "value": alert.timestamp, "short": True},
                    ],
                }
            ],
            "blocks": [
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*🚨 SentinelAI {alert.severity.upper()} Alert*\n{alert.description}"}},
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": f"*Tenant:*\n{alert.tenant_id}"},
                    {"type": "mrkdwn", "text": f"*Risk Score:*\n{alert.risk_score:.2f}"},
                    {"type": "mrkdwn", "text": f"*Type:*\n{alert.event_type}"},
                    {"type": "mrkdwn", "text": f"*Action:*\n{alert.recommended_action}"},
                ]},
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*MITRE:* {alert.details.get('mitre_technique', 'N/A')}"}},
                {"type": "divider"},
                {"type": "section", "text": {"type": "mrkdwn", "text": f"<${alert.details.get('dashboard_url', alert.details.get('dashboard_url', CONFIG.websocket_server_url))}|View timeline replay>"}},
            ],
        }

        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            webhook_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        def send() -> bool:
            with urllib.request.urlopen(request, timeout=5) as response:
                if response.status != 200:
                    raise RuntimeError(f"Slack webhook returned {response.status}")
                return True

        return _retry(send, attempts=3, base_delay=0.2, factor=2.0)

    @staticmethod
    def _slack_color(severity: str) -> str:
        return {
            "critical": "#d50200",
            "high": "#ff8c00",
            "medium": "#f2c744",
            "low": "#36a64f",
        }.get(severity.lower(), "#8e8e8e")


class EmailNotifier:
    def send_email(self, alert: AlertPayload, recipients: list[str]) -> bool:
        if not recipients:
            raise ValueError("No email recipients configured for tenant.")

        message = EmailMessage()
        message["Subject"] = f"[{alert.severity.upper()}] Security Alert - {alert.host or alert.user or alert.event_type}"
        message["From"] = CONFIG.alert_from_address
        message["To"] = ", ".join(recipients)
        body_lines = [
            f"SentinelAI Security Alert",
            "", 
            f"Severity: {alert.severity}",
            f"Risk Score: {alert.risk_score:.2f}",
            f"Tenant: {alert.tenant_id}",
            f"Event Type: {alert.event_type}",
            f"User: {alert.user}",
            f"Host: {alert.host}",
            f"Recommended Action: {alert.recommended_action}",
            "", 
            f"Description: {alert.description}",
            "", 
            f"Timeline Replay: {alert.details.get('dashboard_url', CONFIG.websocket_server_url)}",
        ]
        message.set_content("\n".join(body_lines))

        def send() -> bool:
            if CONFIG.smtp_use_tls:
                context = ssl.create_default_context()
                with smtplib.SMTP(CONFIG.smtp_server, CONFIG.smtp_port, timeout=10) as smtp:
                    smtp.starttls(context=context)
                    if CONFIG.smtp_username and CONFIG.smtp_password:
                        smtp.login(CONFIG.smtp_username, CONFIG.smtp_password)
                    smtp.send_message(message)
            else:
                with smtplib.SMTP(CONFIG.smtp_server, CONFIG.smtp_port, timeout=10) as smtp:
                    if CONFIG.smtp_username and CONFIG.smtp_password:
                        smtp.login(CONFIG.smtp_username, CONFIG.smtp_password)
                    smtp.send_message(message)
            return True

        return _retry(send, attempts=3, base_delay=0.2, factor=2.0)


class KillSwitchEngine:
    def __init__(self) -> None:
        self.approvals: dict[str, dict[str, Any]] = {}

    def evaluate(self, alert: AlertPayload) -> bool:
        return alert.severity.lower() == "critical"

    def require_approval(self, alert: AlertPayload, tenant_config: TenantDispatchConfig) -> bool:
        if not self.evaluate(alert):
            return False
        if tenant_config.auto_response_allowed:
            return False
        return True

    def is_action_allowed(self, action: str, tenant_config: TenantDispatchConfig) -> bool:
        return action in tenant_config.allowlist_actions

    def approve(self, payload: KillSwitchApproveRequest) -> dict[str, Any]:
        self.approvals[payload.alert_id] = {
            "alert_id": payload.alert_id,
            "action": payload.action,
            "approver": payload.approver,
            "approved": payload.approved,
            "reason": payload.reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        append_jsonl(CONFIG.kill_switch_store, self.approvals[payload.alert_id])
        return self.approvals[payload.alert_id]

    def execute(self, alert: AlertPayload, action: str, approved: bool = False, tenant_config: TenantDispatchConfig | None = None) -> dict[str, Any]:
        if tenant_config is None:
            tenant_config = DEFAULT_TENANT_CONFIGS.get(alert.tenant_id, DEFAULT_TENANT_CONFIGS["default"])

        if not self.is_action_allowed(action, tenant_config):
            return {"status": "blocked", "reason": f"Action '{action}' is not allowed for tenant."}

        if not approved and self.require_approval(alert, tenant_config):
            return {"status": "pending_approval", "reason": "Critical response requires approval before execution."}

        record = {
            "alert_id": alert.alert_id,
            "tenant_id": alert.tenant_id,
            "action": action,
            "approved": approved,
            "auto_response_allowed": tenant_config.auto_response_allowed,
            "severity": alert.severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "executed" if approved or tenant_config.auto_response_allowed else "skipped",
            "details": alert.details,
        }
        append_jsonl(CONFIG.kill_switch_store, record)
        logger.info("Kill-switch event recorded: %s", record)
        return record


class AlertEngine:
    def __init__(self) -> None:
        self.tenant_configs = DEFAULT_TENANT_CONFIGS
        self.slack_notifier = SlackNotifier()
        self.email_notifier = EmailNotifier()
        self.kill_switch_engine = KillSwitchEngine()
        self.deduplication_cache: dict[str, float] = {}
        self.rate_limits: dict[str, list[float]] = {}

    def register_tenant(self, config: TenantDispatchConfig) -> None:
        self.tenant_configs[config.tenant_id] = config

    def load_tenant_config(self, tenant_id: str) -> TenantDispatchConfig:
        return self.tenant_configs.get(tenant_id, self.tenant_configs["default"])

    def evaluate(self, event: dict[str, Any]) -> AlertPayload:
        event = normalize_event(event)
        tenant_id = str(event.get("tenant_id", "default") or "default")
        risk_score = float(event.get("risk_score", 0.0) or 0.0)
        event_type = str(event.get("event_type", "unknown"))
        severity = str(event.get("severity", self._severity_from_score(risk_score)))
        description = self._build_description(event)
        recommended_action = self._recommend_action(severity, event)
        details = {
            "mitre_technique": str(event.get("mitre_technique", "N/A")),
            "dashboard_url": self.load_tenant_config(tenant_id).dashboard_url,
            "source": str(event.get("source", "unknown")),
            "attack_type": str(event.get("attack_type", "unknown")),
        }

        return AlertPayload(
            alert_id=str(uuid4()),
            tenant_id=tenant_id,
            severity=severity,
            event_type=event_type,
            risk_score=risk_score,
            host=str(event.get("host") or event.get("destination_host") or event.get("source_host") or event.get("remote_ip") or "unknown"),
            user=str(event.get("user") or event.get("user_id") or "unknown"),
            timestamp=str(event.get("timestamp") or datetime.now(timezone.utc).isoformat()),
            description=description,
            recommended_action=recommended_action,
            details=details,
        )

    def route_alert(self, alert: AlertPayload) -> TenantDispatchConfig:
        return self.load_tenant_config(alert.tenant_id)

    def trigger_notifications(self, alert: AlertPayload) -> dict[str, Any]:
        tenant_config = self.route_alert(alert)
        if not alert or self._is_rate_limited(alert.tenant_id):
            logger.warning("Alert rate limit triggered for tenant=%s", alert.tenant_id)
            return {"status": "rate_limited", "alert_id": alert.alert_id}

        if self._is_duplicate(alert):
            logger.info("Duplicate alert suppressed: %s", alert.alert_id)
            return {"status": "duplicate", "alert_id": alert.alert_id}

        response = {"alert_id": alert.alert_id, "tenant_id": alert.tenant_id, "notifications": []}
        append_jsonl(CONFIG.alert_store, alert.model_dump())

        if tenant_config.slack_webhook:
            try:
                self.slack_notifier.send_slack_alert(alert, tenant_config.slack_webhook)
                response["notifications"].append("slack")
            except Exception as exc:
                log_health_event("error", "slack_notification", "Slack alert failed", context={"error": str(exc), "alert_id": alert.alert_id})
                response["notifications"].append("slack_failed")
                append_jsonl(CONFIG.alert_dlq_store, {**alert.model_dump(), "failure": str(exc), "channel": "slack"})

        if tenant_config.email_recipients:
            try:
                self.email_notifier.send_email(alert, tenant_config.email_recipients)
                response["notifications"].append("email")
            except Exception as exc:
                log_health_event("error", "email_notification", "Email alert failed", context={"error": str(exc), "alert_id": alert.alert_id})
                response["notifications"].append("email_failed")
                append_jsonl(CONFIG.alert_dlq_store, {**alert.model_dump(), "failure": str(exc), "channel": "email"})

        if alert.severity.lower() == "critical":
            response["kill_switch"] = self.kill_switch_engine.execute(
                alert,
                action=alert.recommended_action,
                approved=tenant_config.auto_response_allowed,
                tenant_config=tenant_config,
            )

        self._record_sent(alert)
        return response

    def send_slack_test(self, payload: AlertTestRequest) -> dict[str, Any]:
        alert = self._build_test_alert(payload)
        tenant_config = self.load_tenant_config(alert.tenant_id)
        if not tenant_config.slack_webhook:
            raise ValueError("No Slack webhook configured for tenant.")
        self.slack_notifier.send_slack_alert(alert, tenant_config.slack_webhook)
        return alert.model_dump()

    def send_email_test(self, payload: AlertTestRequest) -> dict[str, Any]:
        alert = self._build_test_alert(payload)
        tenant_config = self.load_tenant_config(alert.tenant_id)
        self.email_notifier.send_email(alert, tenant_config.email_recipients)
        return alert.model_dump()

    def _build_test_alert(self, payload: AlertTestRequest) -> AlertPayload:
        severity = payload.severity or "high"
        return AlertPayload(
            alert_id=str(uuid4()),
            tenant_id=payload.tenant_id or "default",
            severity=severity,
            event_type=payload.event_type or "test_event",
            risk_score=payload.risk_score if payload.risk_score is not None else 85.0,
            host=payload.host or "test-host",
            user=payload.user or "test-user",
            timestamp=datetime.now(timezone.utc).isoformat(),
            description=payload.description or "This is a SentinelAI alert test message.",
            recommended_action=payload.recommended_action or "monitor",
            details={"dashboard_url": self.load_tenant_config(payload.tenant_id or "default").dashboard_url},
        )

    def _build_description(self, event: dict[str, Any]) -> str:
        attack_type = event.get("attack_type") or "unknown"
        mitre = event.get("mitre_technique") or "N/A"
        summary_parts = [
            f"Event type: {event.get('event_type', 'unknown')}",
            f"Source: {event.get('source', 'unknown')}",
            f"Attack type: {attack_type}",
            f"MITRE technique: {mitre}",
            f"Risk score: {event.get('risk_score', 0.0):.2f}",
        ]
        return " | ".join(summary_parts)

    def _recommend_action(self, severity: str, event: dict[str, Any]) -> str:
        if severity.lower() == "critical":
            return "kill_process"
        if severity.lower() == "high":
            return "isolate_host"
        if event.get("attack_type") in ("brute_force", "privilege_escalation"):
            return "block_ip"
        return "monitor"

    @staticmethod
    def _severity_from_score(score: float) -> str:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 30:
            return "medium"
        return "low"

    def _is_duplicate(self, alert: AlertPayload) -> bool:
        key = f"{alert.tenant_id}:{alert.host}:{alert.user}:{alert.event_type}:{alert.recommended_action}"
        now = time.time()
        expired = [k for k, ts in self.deduplication_cache.items() if now - ts > 180]
        for k in expired:
            self.deduplication_cache.pop(k, None)
        if key in self.deduplication_cache:
            return True
        self.deduplication_cache[key] = now
        return False

    def _is_rate_limited(self, tenant_id: str) -> bool:
        now = time.time()
        window = self.rate_limits.setdefault(tenant_id, [])
        window[:] = [ts for ts in window if now - ts < 60]
        if len(window) >= 15:
            return True
        window.append(now)
        return False

    def _record_sent(self, alert: AlertPayload) -> None:
        self.rate_limits.setdefault(alert.tenant_id, []).append(time.time())


class AlertKafkaConsumerService:
    def __init__(self, topics: list[str] | None = None, bootstrap_servers: list[str] | None = None, group_id: str = "sentinelai-alert-engine") -> None:
        self.topics = topics or [CONFIG.kafka_scored_topic, CONFIG.kafka_alerts_topic]
        self.bootstrap_servers = bootstrap_servers or CONFIG.kafka_bootstrap_servers
        self.group_id = group_id
        self.running = False
        self.consumer: KafkaConsumer | None = None

    def connect(self) -> bool:
        if ConfluentConsumer is None:
            logger.warning("Confluent Kafka consumer unavailable; alert Kafka bridge will not start.")
            return False

        try:
            self.consumer = ConfluentConsumer(
                {
                    "bootstrap.servers": ",".join(self.bootstrap_servers),
                    "group.id": self.group_id,
                    "auto.offset.reset": "latest",
                    "enable.auto.commit": True,
                }
            )
            self.consumer.subscribe(self.topics)
            return True
        except Exception as exc:
            logger.error("Failed to connect to Kafka alert topics: %s", exc)
            return False

    def consume(self) -> None:
        if self.consumer is None and not self.connect():
            return
        self.running = True
        logger.info("AlertKafkaConsumerService connected to %s", self.topics)
        while self.running and self.consumer is not None:
            for record in self.consumer:
                try:
                    payload = record.value
                    alert = alert_engine.evaluate(payload)
                    if alert and alert.risk_score >= 30:
                        alert_engine.trigger_notifications(alert)
                except Exception as exc:
                    logger.error("Alert consumer error: %s", exc)
            time.sleep(0.1)

    def shutdown(self) -> None:
        self.running = False
        if self.consumer is not None:
            try:
                self.consumer.close()
            except Exception:
                pass


alert_engine = AlertEngine()
alert_kafka_consumer = AlertKafkaConsumerService()