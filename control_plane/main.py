from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from billing.service import BillingService, UsageSnapshot
from control_plane.bootstrap import bootstrap_defaults
from control_plane.database import Base, get_db, get_engine, set_tenant_context
from control_plane.dependencies import enforce_rate_limit, get_current_claims, get_current_user, require_roles
from control_plane.middleware import request_logging_middleware
from control_plane.models import Agent, AuditLog, Incident, Policy, RefreshToken, Subscription, Tenant, UsageMetric, User
from control_plane.schemas import (
    AgentCreate,
    AgentEnrollmentRequest,
    AgentHeartbeatRequest,
    AgentProvisioningResponse,
    AgentRead,
    IncidentCreate,
    IncidentRead,
    LoginRequest,
    PolicyCreate,
    PolicyRead,
    RefreshRequest,
    SignupRequest,
    SignupResponse,
    SubscriptionRead,
    TenantCreate,
    TenantRead,
    TokenPair,
    UsageMetricRead,
    UserCreate,
)
from control_plane.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    hash_token,
    verify_password,
)
from observability.metrics import AGENT_HEARTBEAT_HEALTH, SERVICE_HEALTH, export_prometheus, write_snapshot


app = FastAPI(title="SentinelAI Control Plane", version="0.1.0")
app.middleware("http")(request_logging_middleware)
_HEARTBEAT_NONCES: set[str] = set()
_billing = BillingService()


@app.on_event("startup")
def startup() -> None:
    Base.metadata.create_all(bind=get_engine())
    with Session(bind=get_engine()) as db:
        bootstrap_defaults(db)


def _audit(db: Session, *, tenant_id: str, actor_user_id: str | None, action: str, target: str, metadata: dict) -> None:
    db.add(AuditLog(tenant_id=tenant_id, actor_user_id=actor_user_id, action=action, target_resource=target, audit_metadata=metadata))


def _update_usage(db: Session, tenant_id: str, *, api_calls: int = 0) -> None:
    metric = db.execute(
        select(UsageMetric).where(UsageMetric.tenant_id == tenant_id).order_by(desc(UsageMetric.timestamp))
    ).scalar_one_or_none()
    if metric is None:
        metric = UsageMetric(tenant_id=tenant_id)
        db.add(metric)
        db.flush()
    metric.api_calls += api_calls


def _tenant_defaults(plan: str) -> dict[str, int]:
    limits = _billing.plan_limits(plan)
    return {
        "agent_limit": 10 if plan == "free" else 250 if plan == "pro" else 5000,
        "eps_limit": limits["events_per_second"],
        "storage_limit_mb": 1024 if plan == "free" else 20_480 if plan == "pro" else 204_800,
        "retention_days": 7 if plan == "free" else 30 if plan == "pro" else 180,
    }


@app.get("/")
def root() -> dict[str, str]:
    return {"service": "sentinelai-control-plane", "status": "ok"}


@app.get("/metrics")
def metrics() -> Response:
    return Response(content=export_prometheus(), media_type="text/plain; version=0.0.4")


@app.get("/health")
def health() -> dict[str, str]:
    SERVICE_HEALTH.labels(service="control-plane-api").set(1)
    return {"service": "control-plane-api", "status": "healthy"}


@app.post("/auth/login", response_model=TokenPair)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenPair:
    user = db.execute(select(User).where(User.email == payload.email)).scalar_one_or_none()
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token = create_access_token(user.id, user.tenant_id, user.role)
    refresh_token = create_refresh_token(user.id, user.tenant_id, user.role)
    db.add(
        RefreshToken(
            user_id=user.id,
            tenant_id=user.tenant_id,
            token_hash=hash_token(refresh_token),
            expires_at=datetime.utcnow() + timedelta(minutes=43200),
        )
    )
    _update_usage(db, user.tenant_id, api_calls=1)
    db.commit()
    return TokenPair(access_token=access_token, refresh_token=refresh_token)


@app.post("/auth/refresh", response_model=TokenPair)
def refresh(payload: RefreshRequest, db: Session = Depends(get_db)) -> TokenPair:
    claims = decode_token(payload.refresh_token)
    if claims.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token required")

    token_row = db.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == hash_token(payload.refresh_token),
            RefreshToken.revoked.is_(False),
        )
    ).scalar_one_or_none()
    if token_row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token revoked")

    access_token = create_access_token(claims["user_id"], claims["tenant_id"], claims["role"])
    refresh_token = create_refresh_token(claims["user_id"], claims["tenant_id"], claims["role"])
    token_row.revoked = True
    db.add(
        RefreshToken(
            user_id=claims["user_id"],
            tenant_id=claims["tenant_id"],
            token_hash=hash_token(refresh_token),
            expires_at=datetime.utcnow() + timedelta(minutes=43200),
        )
    )
    _update_usage(db, claims["tenant_id"], api_calls=1)
    db.commit()
    return TokenPair(access_token=access_token, refresh_token=refresh_token)


@app.get("/tenants", response_model=list[TenantRead], dependencies=[Depends(enforce_rate_limit)])
def list_tenants(
    claims: dict = Depends(require_roles("admin", "system_operator")),
    db: Session = Depends(get_db),
) -> list[Tenant]:
    if claims["role"] == "system_operator":
        return list(db.execute(select(Tenant).order_by(Tenant.created_at)).scalars().all())
    set_tenant_context(db, claims["tenant_id"])
    tenant = db.execute(select(Tenant).where(Tenant.id == claims["tenant_id"])).scalar_one()
    return [tenant]


@app.post("/tenants", response_model=TenantRead)
def create_tenant(
    payload: TenantCreate,
    db: Session = Depends(get_db),
    claims: dict = Depends(require_roles("system_operator")),
) -> Tenant:
    defaults = _tenant_defaults(payload.plan)
    namespace = payload.namespace or f"tenant-{payload.name.lower().replace(' ', '-')}"
    tenant = Tenant(
        name=payload.name,
        plan=payload.plan,
        status=payload.status,
        namespace=namespace,
        kafka_topic_prefix=f"{namespace}-events",
        **defaults,
    )
    db.add(tenant)
    db.flush()
    db.add(UsageMetric(tenant_id=tenant.id))
    db.add(Subscription(tenant_id=tenant.id, plan=payload.plan, status="active"))
    _audit(db, tenant_id=tenant.id, actor_user_id=claims["user_id"], action="create_tenant", target="tenant", metadata={"name": payload.name})
    db.commit()
    db.refresh(tenant)
    return tenant


@app.post("/signup", response_model=SignupResponse)
def signup(payload: SignupRequest, db: Session = Depends(get_db)) -> SignupResponse:
    namespace = f"tenant-{payload.tenant_name.lower().replace(' ', '-')}"
    defaults = _tenant_defaults(payload.plan)
    tenant = Tenant(
        name=payload.tenant_name,
        plan=payload.plan,
        status="active",
        namespace=namespace,
        kafka_topic_prefix=f"{namespace}-events",
        **defaults,
    )
    db.add(tenant)
    db.flush()
    user = User(
        tenant_id=tenant.id,
        email=payload.admin_email,
        password_hash=hash_password(payload.password),
        role="admin",
    )
    db.add(user)
    db.add(UsageMetric(tenant_id=tenant.id))
    db.add(Subscription(tenant_id=tenant.id, plan=payload.plan, status="active"))
    _audit(
        db,
        tenant_id=tenant.id,
        actor_user_id=None,
        action="tenant_signup",
        target="tenant",
        metadata={"tenant_name": payload.tenant_name, "admin_email": payload.admin_email},
    )
    db.commit()
    checkout = _billing.create_subscription(tenant_id=tenant.id, plan=payload.plan)
    return SignupResponse(
        tenant_id=tenant.id,
        tenant_name=tenant.name,
        user_id=user.id,
        namespace=tenant.namespace,
        kafka_topic_prefix=tenant.kafka_topic_prefix,
        checkout_session_id=checkout["checkout_session_id"],
    )


@app.post("/tenants/{tenant_id}/users", response_model=dict[str, str])
def create_user(
    tenant_id: str,
    payload: UserCreate,
    db: Session = Depends(get_db),
    claims: dict = Depends(require_roles("admin", "system_operator")),
) -> dict[str, str]:
    if claims["role"] != "system_operator" and claims["tenant_id"] != tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tenant mismatch")
    user = User(tenant_id=tenant_id, email=payload.email, password_hash=hash_password(payload.password), role=payload.role)
    db.add(user)
    _audit(db, tenant_id=tenant_id, actor_user_id=claims["user_id"], action="create_user", target="user", metadata={"email": payload.email, "role": payload.role})
    db.commit()
    return {"user_id": user.id, "tenant_id": tenant_id}


@app.get("/agents", response_model=list[AgentRead], dependencies=[Depends(enforce_rate_limit)])
def list_agents(
    claims: dict = Depends(get_current_claims),
    db: Session = Depends(get_db),
) -> list[Agent]:
    set_tenant_context(db, claims["tenant_id"])
    _update_usage(db, claims["tenant_id"], api_calls=1)
    db.commit()
    return list(db.execute(select(Agent).where(Agent.tenant_id == claims["tenant_id"]).order_by(Agent.created_at.desc())).scalars().all())


@app.post("/agents", response_model=AgentProvisioningResponse)
def create_agent(
    payload: AgentCreate,
    db: Session = Depends(get_db),
    claims: dict = Depends(require_roles("admin", "system_operator")),
) -> AgentProvisioningResponse:
    tenant_id = claims["tenant_id"]
    tenant = db.execute(select(Tenant).where(Tenant.id == tenant_id)).scalar_one()
    agent_count = len(list(db.execute(select(Agent).where(Agent.tenant_id == tenant_id)).scalars().all()))
    if agent_count >= tenant.agent_limit:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Agent quota exceeded")
    agent = Agent(
        tenant_id=tenant_id,
        hostname=payload.hostname,
        os=payload.os,
        status="active",
        agent_version=payload.agent_version,
        machine_id=payload.machine_id,
        enrollment_token=str(uuid4()),
        kafka_username=f"agent-{uuid4()}",
        kafka_password=str(uuid4()),
    )
    db.add(agent)
    _audit(db, tenant_id=tenant_id, actor_user_id=claims["user_id"], action="create_agent", target="agent", metadata={"hostname": payload.hostname})
    _update_usage(db, tenant_id, api_calls=1)
    db.commit()
    db.refresh(agent)
    return AgentProvisioningResponse(
        id=agent.id,
        tenant_id=agent.tenant_id,
        hostname=agent.hostname,
        os=agent.os,
        status=agent.status,
        last_heartbeat=agent.last_heartbeat,
        agent_version=agent.agent_version,
        machine_id=agent.machine_id,
        enrollment_token=agent.enrollment_token,
        kafka_username=agent.kafka_username,
        kafka_password=agent.kafka_password,
    )


@app.post("/agents/enroll")
def enroll_agent(payload: AgentEnrollmentRequest, db: Session = Depends(get_db)) -> dict[str, str]:
    agent = db.execute(select(Agent).where(Agent.enrollment_token == payload.enrollment_token)).scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid enrollment token")
    agent.hostname = payload.hostname
    agent.os = payload.os
    agent.machine_id = payload.machine_id
    agent.agent_version = payload.agent_version
    agent.last_heartbeat = datetime.utcnow()
    _audit(db, tenant_id=agent.tenant_id, actor_user_id=None, action="agent_enroll", target=agent.id, metadata={"hostname": payload.hostname})
    db.commit()
    return {
        "agent_id": agent.id,
        "tenant_id": agent.tenant_id,
        "kafka_topic": "tenant-events",
        "kafka_username": agent.kafka_username or "",
        "kafka_password": agent.kafka_password or "",
    }


@app.post("/agents/{agent_id}/heartbeat")
def agent_heartbeat(
    agent_id: str,
    payload: AgentHeartbeatRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    agent = db.execute(select(Agent).where(Agent.id == agent_id)).scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    timestamp_header = request.headers.get("x-agent-timestamp")
    nonce = request.headers.get("x-agent-nonce")
    signature = request.headers.get("x-agent-signature")
    if not timestamp_header or not nonce or not signature:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing signed heartbeat headers")
    try:
        ts = int(timestamp_header)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid heartbeat timestamp") from exc
    if abs(int(datetime.now(timezone.utc).timestamp()) - ts) > 120:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Stale heartbeat rejected")
    nonce_key = f"{agent_id}:{nonce}:{ts}"
    if nonce_key in _HEARTBEAT_NONCES:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Replay heartbeat rejected")
    expected_signature = hmac.new(
        key=(agent.machine_id or "sentinelai").encode("utf-8"),
        msg=f"{agent_id}:{ts}:{nonce}".encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid heartbeat signature")
    _HEARTBEAT_NONCES.add(nonce_key)
    agent.last_heartbeat = datetime.utcnow()
    agent.status = "active" if payload.agent_health.lower() == "healthy" else "degraded"
    _audit(
        db,
        tenant_id=agent.tenant_id,
        actor_user_id=None,
        action="agent_heartbeat",
        target=agent_id,
        metadata=payload.model_dump(),
    )
    metric = db.execute(
        select(UsageMetric).where(UsageMetric.tenant_id == agent.tenant_id).order_by(desc(UsageMetric.timestamp))
    ).scalar_one_or_none()
    if metric is None:
        metric = UsageMetric(tenant_id=agent.tenant_id)
        db.add(metric)
    metric.api_calls += 1
    AGENT_HEARTBEAT_HEALTH.labels(tenant_id=agent.tenant_id, agent_id=agent.id).set(1 if agent.status == "active" else 0)
    write_snapshot(
        {
            "services": {
                "control_plane_api": "healthy",
            },
            "agents": {
                "last_heartbeat_agent_id": agent.id,
                "tenant_id": agent.tenant_id,
                "status": agent.status,
                "queue_depth": payload.queue_depth,
            },
        }
    )
    db.commit()
    return {"status": "ok"}


@app.get("/policies", response_model=list[PolicyRead], dependencies=[Depends(enforce_rate_limit)])
def list_policies(claims: dict = Depends(get_current_claims), db: Session = Depends(get_db)) -> list[Policy]:
    return list(db.execute(select(Policy).where(Policy.tenant_id == claims["tenant_id"]).order_by(Policy.created_at.desc())).scalars().all())


@app.post("/policies", response_model=PolicyRead)
def create_policy(
    payload: PolicyCreate,
    db: Session = Depends(get_db),
    claims: dict = Depends(require_roles("admin", "system_operator")),
) -> Policy:
    policy = Policy(
        tenant_id=claims["tenant_id"],
        name=payload.name,
        description=payload.description,
        enabled=payload.enabled,
        conditions=payload.conditions,
        actions=payload.actions,
    )
    db.add(policy)
    _audit(db, tenant_id=claims["tenant_id"], actor_user_id=claims["user_id"], action="create_policy", target=policy.name, metadata=payload.model_dump())
    _update_usage(db, claims["tenant_id"], api_calls=1)
    db.commit()
    db.refresh(policy)
    return policy


@app.get("/incidents", response_model=list[IncidentRead], dependencies=[Depends(enforce_rate_limit)])
def list_incidents(claims: dict = Depends(get_current_claims), db: Session = Depends(get_db)) -> list[Incident]:
    return list(db.execute(select(Incident).where(Incident.tenant_id == claims["tenant_id"]).order_by(Incident.created_at.desc())).scalars().all())


@app.post("/incidents", response_model=IncidentRead)
def create_incident(
    payload: IncidentCreate,
    db: Session = Depends(get_db),
    claims: dict = Depends(require_roles("admin", "analyst", "system_operator")),
) -> Incident:
    incident = Incident(
        tenant_id=claims["tenant_id"],
        severity=payload.severity,
        ml_score=payload.ml_score,
        status=payload.status,
        title=payload.title,
        description=payload.description,
        incident_metadata=payload.metadata,
    )
    db.add(incident)
    _audit(db, tenant_id=claims["tenant_id"], actor_user_id=claims["user_id"], action="create_incident", target=incident.title, metadata=payload.model_dump())
    _update_usage(db, claims["tenant_id"], api_calls=1, )
    db.commit()
    db.refresh(incident)
    return incident


@app.get("/billing/usage", response_model=list[UsageMetricRead], dependencies=[Depends(enforce_rate_limit)])
def get_billing_usage(
    claims: dict = Depends(require_roles("admin", "system_operator")),
    db: Session = Depends(get_db),
) -> list[UsageMetric]:
    tenant_id = claims["tenant_id"]
    return list(db.execute(select(UsageMetric).where(UsageMetric.tenant_id == tenant_id).order_by(UsageMetric.timestamp.desc())).scalars().all())


@app.get("/subscriptions/current", response_model=SubscriptionRead)
def current_subscription(
    claims: dict = Depends(get_current_claims),
    db: Session = Depends(get_db),
) -> Subscription:
    set_tenant_context(db, claims["tenant_id"])
    subscription = db.execute(
        select(Subscription).where(Subscription.tenant_id == claims["tenant_id"]).order_by(desc(Subscription.created_at))
    ).scalar_one_or_none()
    if subscription is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Subscription not found")
    return subscription


@app.get("/provisioning/tenant/{tenant_id}")
def tenant_provisioning(
    tenant_id: str,
    claims: dict = Depends(require_roles("admin", "system_operator")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    if claims["role"] != "system_operator" and claims["tenant_id"] != tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tenant mismatch")
    tenant = db.execute(select(Tenant).where(Tenant.id == tenant_id)).scalar_one()
    latest_usage = db.execute(
        select(UsageMetric).where(UsageMetric.tenant_id == tenant_id).order_by(desc(UsageMetric.timestamp))
    ).scalar_one_or_none()
    snapshot = UsageSnapshot(
        tenant_id=tenant_id,
        events_ingested=getattr(latest_usage, "events_ingested", 0),
        api_calls=getattr(latest_usage, "api_calls", 0),
        ml_predictions=getattr(latest_usage, "ml_inference_count", 0),
    )
    return {
        "tenant_id": tenant.id,
        "namespace": tenant.namespace,
        "kafka_topic": tenant.kafka_topic_prefix,
        "database_schema": "public",
        "quotas": _billing.evaluate_usage(tenant.plan, snapshot),
        "compliance_mode": {
            "retention_days": tenant.retention_days,
            "audit_logging": True,
            "sso_ready": True,
        },
    }
