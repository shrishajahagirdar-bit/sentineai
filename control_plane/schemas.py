from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class TenantCreate(BaseModel):
    name: str
    plan: str = Field(pattern="^(free|pro|enterprise)$")
    status: str = "active"
    namespace: str | None = None


class TenantRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    plan: str
    created_at: datetime
    status: str
    namespace: str
    kafka_topic_prefix: str
    agent_limit: int
    eps_limit: int
    storage_limit_mb: int
    retention_days: int


class SignupRequest(BaseModel):
    tenant_name: str
    admin_email: EmailStr
    password: str
    plan: str = Field(pattern="^(free|pro|enterprise)$")


class SignupResponse(BaseModel):
    tenant_id: str
    tenant_name: str
    user_id: str
    namespace: str
    kafka_topic_prefix: str
    checkout_session_id: str

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    role: str = Field(pattern="^(admin|analyst|viewer|system_operator)$")


class AgentCreate(BaseModel):
    hostname: str
    os: str
    agent_version: str = "0.1.0"
    machine_id: str | None = None


class AgentEnrollmentRequest(BaseModel):
    enrollment_token: str
    hostname: str
    os: str
    agent_version: str
    machine_id: str


class AgentHeartbeatRequest(BaseModel):
    cpu_usage: float
    memory_usage: float
    active_processes: int
    agent_health: str
    queue_depth: int = 0


class AgentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    hostname: str
    os: str
    status: str
    last_heartbeat: datetime | None
    agent_version: str
    machine_id: str | None = None

class AgentProvisioningResponse(AgentRead):
    enrollment_token: str | None = None
    kafka_username: str | None = None
    kafka_password: str | None = None


class PolicyCreate(BaseModel):
    name: str
    description: str = ""
    enabled: bool = True
    conditions: dict[str, Any] = Field(default_factory=dict)
    actions: dict[str, Any] = Field(default_factory=dict)


class PolicyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    name: str
    description: str
    enabled: bool
    conditions: dict[str, Any]
    actions: dict[str, Any]
    created_at: datetime

class IncidentCreate(BaseModel):
    severity: str = Field(pattern="^(low|medium|high|critical)$")
    ml_score: float = 0.0
    status: str = "open"
    title: str = "SentinelAI Incident"
    description: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class IncidentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    severity: str
    ml_score: float
    status: str
    created_at: datetime
    title: str
    description: str
    metadata: dict[str, Any] = Field(validation_alias="incident_metadata")

class UsageMetricRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    tenant_id: str
    timestamp: datetime
    events_ingested: int
    api_calls: int
    ml_inference_count: int
    storage_mb: float


class SubscriptionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    plan: str
    status: str
    billing_cycle: str
    created_at: datetime
