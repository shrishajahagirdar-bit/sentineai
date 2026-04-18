from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from uuid import uuid4


@dataclass
class ResponseAction:
    tenant_id: str
    requested_by: str
    reason: str
    action_type: str
    target: str
    requires_approval: bool = True
    approved: bool = False
    status: str = "pending"
    action_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, str | bool]:
        return asdict(self)
