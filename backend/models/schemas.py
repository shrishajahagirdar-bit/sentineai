from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    event_id: str | None = None
    dataset: str | None = None
    timestamp: datetime | None = None
    user_id: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_host: str | None = None
    destination_host: str | None = None
    device_id: str | None = None
    action: str | None = None
    failed_logins: int = 0
    unusual_location: bool = False
    unusual_time: bool = False
    sensitive_file_access: bool = False
    bulk_download: bool = False
    privilege_escalation: bool = False
    bytes_sent: float | None = None
    bytes_received: float | None = None
    raw_features: dict[str, Any] = Field(default_factory=dict)


class FeedbackRequest(BaseModel):
    event_id: str
    label: str = Field(pattern="^(false_positive|confirmed_threat)$")
    analyst: str | None = None
    notes: str | None = None
    timestamp: datetime | None = None


class UserProfileResponse(BaseModel):
    user_id: str
    login_time_distribution: dict[str, float]
    location_history: list[str]
    device_fingerprint: list[str]
    activity_sequence_model: list[str]
    risk_factors: list[str]


class RiskResponse(BaseModel):
    event_id: str | None
    risk_score: float
    severity: str
    response_action: str
    supervised_probability: float
    anomaly_score: float
    behavior_deviation_score: float
    triggered_rules: list[str]
    explanation: str
    incident_story: str


class AlertPayload(BaseModel):
    alert_id: str
    tenant_id: str
    severity: str
    event_type: str
    risk_score: float
    host: str | None = None
    user: str | None = None
    timestamp: str | None = None
    description: str | None = None
    recommended_action: str
    details: dict[str, Any] = Field(default_factory=dict)


class AlertEvaluateRequest(BaseModel):
    tenant_id: str | None = None
    event_id: str | None = None
    event_type: str | None = None
    severity: str | None = None
    risk_score: float | None = None
    host: str | None = None
    user: str | None = None
    timestamp: datetime | None = None
    description: str | None = None
    attack_type: str | None = None
    mitre_technique: str | None = None
    source: str | None = None
    parsed_fields: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AlertTestRequest(BaseModel):
    tenant_id: str | None = None
    severity: str | None = "high"
    event_type: str | None = "test_event"
    risk_score: float | None = 85.0
    host: str | None = "test-host"
    user: str | None = "test-user"
    description: str | None = "SentinelAI alert test payload"
    recommended_action: str | None = "monitor"


class KillSwitchApproveRequest(BaseModel):
    alert_id: str
    action: str
    approver: str
    approved: bool = False
    reason: str | None = None

