from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from control_plane.config import settings
from control_plane.models import RefreshToken, Subscription, Tenant, UsageMetric, User
from control_plane.security import hash_password


def bootstrap_defaults(db: Session) -> None:
    tenant = db.execute(select(Tenant).where(Tenant.name == "default")).scalar_one_or_none()
    if tenant is None:
        tenant = Tenant(
            name="default",
            plan="enterprise",
            status="active",
            namespace="sentinelai-default",
            kafka_topic_prefix="tenant-events",
            agent_limit=5000,
            eps_limit=5000,
            storage_limit_mb=204800,
            retention_days=180,
        )
        db.add(tenant)
        db.flush()
        db.add(
            UsageMetric(
                tenant_id=tenant.id,
                events_ingested=0,
                api_calls=0,
                ml_inference_count=0,
                storage_mb=0.0,
            )
        )
        db.add(Subscription(tenant_id=tenant.id, plan="enterprise", status="active"))

    user = db.execute(select(User).where(User.email == settings.bootstrap_admin_email)).scalar_one_or_none()
    if user is None:
        db.add(
            User(
                tenant_id=tenant.id,
                email=settings.bootstrap_admin_email,
                password_hash=hash_password(settings.bootstrap_admin_password),
                role="admin",
            )
        )
    db.commit()
