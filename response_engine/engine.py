from __future__ import annotations

from typing import Any

from response_engine.models import ResponseAction
from response_engine.storage import append_audit


ALLOWED_ACTIONS = {
    "isolate_process": "simulated",
    "block_ip": "simulated",
    "kill_process": "guarded",
}


class ResponseEngine:
    def __init__(self, mode: str = "monitor") -> None:
        self.mode = mode

    def request_action(
        self,
        *,
        tenant_id: str,
        requested_by: str,
        reason: str,
        action_type: str,
        target: str,
        approved: bool = False,
    ) -> ResponseAction:
        if action_type not in ALLOWED_ACTIONS:
            raise ValueError(f"Unsupported action_type: {action_type}")

        action = ResponseAction(
            tenant_id=tenant_id,
            requested_by=requested_by,
            reason=reason,
            action_type=action_type,
            target=target,
            approved=approved,
            requires_approval=True,
        )
        if self.mode != "active":
            action.status = "logged_only"
        elif approved:
            action.status = "approved_for_execution"
        else:
            action.status = "awaiting_approval"

        append_audit({**action.to_dict(), "execution_mode": self.mode})
        return action
