from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from control_plane.config import settings
from control_plane.database import get_db, set_tenant_context
from control_plane.models import User
from control_plane.security import decode_token


_RATE_LIMIT_BUCKETS: dict[str, deque[float]] = defaultdict(deque)


def _extract_bearer_token(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    return authorization.split(" ", 1)[1]


def get_current_claims(
    request: Request,
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    token = _extract_bearer_token(authorization)
    try:
        claims = decode_token(token)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {exc}") from exc

    if claims.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token required")

    tenant_id = str(claims.get("tenant_id", ""))
    request.state.tenant_id = tenant_id
    request.state.user_id = str(claims.get("user_id", ""))
    request.state.role = str(claims.get("role", "viewer"))
    set_tenant_context(db, tenant_id)
    return claims


def require_roles(*roles: str):
    def dependency(claims: dict[str, Any] = Depends(get_current_claims)) -> dict[str, Any]:
        role = str(claims.get("role", "viewer"))
        if role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return claims

    return dependency


def get_current_user(
    claims: dict[str, Any] = Depends(get_current_claims),
    db: Session = Depends(get_db),
) -> User:
    result = db.execute(select(User).where(User.id == claims["user_id"], User.tenant_id == claims["tenant_id"]))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
    return user


def enforce_rate_limit(request: Request, claims: dict[str, Any] = Depends(get_current_claims)) -> None:
    tenant_id = str(claims.get("tenant_id", "unknown"))
    now = datetime.now(timezone.utc).timestamp()
    bucket = _RATE_LIMIT_BUCKETS[tenant_id]
    while bucket and now - bucket[0] > 60:
        bucket.popleft()
    if len(bucket) >= settings.api_rate_limit_per_minute:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Tenant rate limit exceeded")
    bucket.append(now)
