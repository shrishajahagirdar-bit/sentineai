from __future__ import annotations

import unittest

from billing.service import BillingService, UsageSnapshot
from response_engine.engine import ResponseEngine


class SaaSExtensionTests(unittest.TestCase):
    def test_billing_limits_evaluate(self) -> None:
        service = BillingService()
        result = service.evaluate_usage(
            "free",
            UsageSnapshot(tenant_id="tenant-1", events_ingested=100, api_calls=50, ml_predictions=100),
        )
        self.assertEqual(result["plan"], "free")
        self.assertTrue(result["within_limits"])

    def test_response_engine_logs_only_in_monitor_mode(self) -> None:
        engine = ResponseEngine(mode="monitor")
        action = engine.request_action(
            tenant_id="tenant-1",
            requested_by="user-1",
            reason="manual triage",
            action_type="block_ip",
            target="203.0.113.10",
            approved=False,
        )
        self.assertEqual(action.status, "logged_only")


if __name__ == "__main__":
    unittest.main()
