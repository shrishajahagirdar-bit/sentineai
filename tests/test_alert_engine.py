from __future__ import annotations

import os
import tempfile
import unittest

from backend.alerting import alert_engine
from backend.models.schemas import AlertTestRequest, KillSwitchApproveRequest


class AlertEngineTests(unittest.TestCase):
    def test_evaluate_builds_alert_payload(self) -> None:
        payload = {
            "tenant_id": "default",
            "event_id": "evt-100",
            "event_type": "anomaly",
            "severity": "high",
            "risk_score": 82.0,
            "host": "web-server-1",
            "user": "svc-admin",
            "timestamp": "2026-04-18T12:00:00Z",
            "attack_type": "privilege_escalation",
            "mitre_technique": "T1055",
        }

        alert = alert_engine.evaluate(payload)
        self.assertEqual(alert.tenant_id, "default")
        self.assertEqual(alert.event_type, "anomaly")
        self.assertEqual(alert.severity, "high")
        self.assertEqual(alert.recommended_action, "isolate_host")
        self.assertTrue(alert.alert_id)

    def test_slack_test_fails_without_webhook(self) -> None:
        request = AlertTestRequest(tenant_id="default")
        with self.assertRaises(ValueError):
            alert_engine.send_slack_test(request)

    def test_kill_switch_approval_records_action(self) -> None:
        request = KillSwitchApproveRequest(
            alert_id="alert-123",
            action="kill_process",
            approver="analyst@example.com",
            approved=True,
            reason="Confirmed critical escalation",
        )
        approval = alert_engine.kill_switch_engine.approve(request)
        self.assertEqual(approval["alert_id"], "alert-123")
        self.assertTrue(approval["approved"])


if __name__ == "__main__":
    unittest.main()
