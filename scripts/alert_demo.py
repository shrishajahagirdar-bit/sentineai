#!/usr/bin/env python3
"""
Alerting System Demo
====================

Demonstrates the real-time alerting system with Slack/Email notifications
and kill-switch approval workflow.

Usage:
    python scripts/alert_demo.py

Features:
- Simulates security events
- Triggers alerts via API
- Shows notification routing
- Demonstrates kill-switch approval
"""

from __future__ import annotations

import json
import time
from typing import Any

import requests

from backend.alerting import alert_engine
from backend.models.schemas import KillSwitchApproveRequest


def simulate_security_event(event_type: str, severity: str = "high") -> dict[str, Any]:
    """Generate a simulated security event."""
    return {
        "tenant_id": "default",
        "event_id": f"demo-{int(time.time())}",
        "event_type": event_type,
        "severity": severity,
        "risk_score": 85.0 if severity == "high" else 95.0,
        "host": "web-server-01",
        "user": "svc-admin",
        "timestamp": f"{time.time():.0f}",
        "attack_type": "privilege_escalation" if event_type == "anomaly" else "brute_force",
        "mitre_technique": "T1055" if event_type == "anomaly" else "T1110",
        "source": "auth",
        "parsed_fields": {
            "ip_address": "192.168.1.100",
            "login_failure_count": 5,
        },
    }


def test_alert_evaluation():
    """Test alert evaluation and notification triggering."""
    print("🚨 Testing Alert Evaluation...")

    # Simulate a high-risk event
    event = simulate_security_event("anomaly", "high")
    print(f"Event: {event['event_type']} | Severity: {event['severity']} | Risk: {event['risk_score']}")

    # Evaluate alert
    alert = alert_engine.evaluate(event)
    print(f"Alert ID: {alert.alert_id}")
    print(f"Severity: {alert.severity}")
    print(f"Recommended Action: {alert.recommended_action}")
    print(f"Description: {alert.description}")

    # Trigger notifications (will fail gracefully without configured webhooks/emails)
    result = alert_engine.trigger_notifications(alert)
    print(f"Notification Result: {result}")

    return alert


def test_kill_switch_approval(alert_id: str):
    """Test kill-switch approval workflow."""
    print("\n🔒 Testing Kill-Switch Approval...")

    # Simulate approval request
    approval_request = KillSwitchApproveRequest(
        alert_id=alert_id,
        action="kill_process",
        approver="security-admin@sentinelai.local",
        approved=True,
        reason="Confirmed privilege escalation attack",
    )

    approval = alert_engine.kill_switch_engine.approve(approval_request)
    print(f"Approval recorded: {approval}")

    return approval


def test_api_endpoints():
    """Test FastAPI alert endpoints."""
    print("\n🌐 Testing API Endpoints...")

    base_url = "http://localhost:8001"

    try:
        # Test alert evaluation
        event = simulate_security_event("anomaly", "critical")
        response = requests.post(
            f"{base_url}/alerts/evaluate",
            json=event,
            timeout=10
        )
        print(f"API Alert Evaluation: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Alert created: {data['data']['alert']['alert_id']}")

        # Test alert history
        response = requests.get(f"{base_url}/alerts/history", timeout=10)
        print(f"API Alert History: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Alert count: {data['data']['count']}")

    except requests.exceptions.RequestException as e:
        print(f"API test failed (server not running?): {e}")


def main():
    """Run the alerting demo."""
    print("🔔 SentinelAI Alerting System Demo")
    print("=" * 50)

    # Test core alert engine
    alert = test_alert_evaluation()

    # Test kill-switch approval
    approval = test_kill_switch_approval(alert.alert_id)

    # Test API endpoints
    test_api_endpoints()

    print("\n✅ Demo completed!")
    print("\nNext steps:")
    print("- Configure Slack webhooks in alert_engine.register_tenant()")
    print("- Configure SMTP settings in sentinel_config.py")
    print("- Start the WebSocket server: python backend/websocket_server.py")
    print("- Run Kafka consumer for real-time alerts")


if __name__ == "__main__":
    main()