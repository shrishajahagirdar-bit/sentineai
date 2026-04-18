from __future__ import annotations

from dataclasses import dataclass

from billing.plans import PLAN_LIMITS
from billing.stripe_mock import create_checkout_session


@dataclass
class UsageSnapshot:
    tenant_id: str
    events_ingested: int
    api_calls: int
    ml_predictions: int


class BillingService:
    def plan_limits(self, plan: str) -> dict[str, int]:
        return PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])

    def evaluate_usage(self, plan: str, snapshot: UsageSnapshot) -> dict[str, object]:
        limits = self.plan_limits(plan)
        return {
            "tenant_id": snapshot.tenant_id,
            "plan": plan,
            "limits": limits,
            "usage": {
                "events_ingested": snapshot.events_ingested,
                "api_calls": snapshot.api_calls,
                "ml_predictions": snapshot.ml_predictions,
            },
            "within_limits": (
                snapshot.api_calls <= limits["api_calls_per_minute"]
                and snapshot.ml_predictions <= limits["ml_predictions_per_day"]
            ),
        }

    def create_subscription(self, *, tenant_id: str, plan: str) -> dict[str, str]:
        return create_checkout_session(tenant_id=tenant_id, plan=plan)
