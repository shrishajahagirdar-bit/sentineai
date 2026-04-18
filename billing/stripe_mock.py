from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4


def create_checkout_session(*, tenant_id: str, plan: str) -> dict[str, str]:
    return {
        "checkout_session_id": str(uuid4()),
        "tenant_id": tenant_id,
        "plan": plan,
        "status": "created",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
