from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, HTTPException

from backend.alerting import alert_engine
from backend.models.schemas import AlertEvaluateRequest, AlertTestRequest, KillSwitchApproveRequest
from backend.services.data_access import load_jsonl
from core.safe_wrapper import safe_execution
from core.transformers import standardize_response
from sentinel_config import CONFIG


router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.post("/evaluate")
@safe_execution(
    default_factory=lambda: standardize_response("fallback", data={}, error="alert evaluation failed"),
    operation="api_alerts_evaluate",
)
def evaluate_alert(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    alert = alert_engine.evaluate(payload)
    result = alert_engine.trigger_notifications(alert)
    return standardize_response(
        "success",
        data={"alert": alert.model_dump(), "result": result},
        metadata={"tenant_id": alert.tenant_id, "severity": alert.severity},
        error=None,
    )


@router.get("/history")
@safe_execution(
    default_factory=lambda: standardize_response("fallback", data={"records": []}, error="alert history failed"),
    operation="api_alerts_history",
)
def alerts_history(limit: int = 100) -> dict[str, Any]:
    records = load_jsonl(CONFIG.alert_store, limit=limit)
    return standardize_response(
        "success",
        data={"records": records},
        metadata={"count": len(records), "limit": limit},
        error=None,
    )


@router.post("/test/slack")
@safe_execution(
    default_factory=lambda: standardize_response("fallback", data={}, error="slack test failed"),
    operation="api_alerts_test_slack",
)
def alerts_test_slack(payload: AlertTestRequest) -> dict[str, Any]:
    test_alert = alert_engine.send_slack_test(payload)
    return standardize_response(
        "success",
        data={"test_alert": test_alert},
        metadata={"tenant_id": payload.tenant_id or "default"},
        error=None,
    )


@router.post("/test/email")
@safe_execution(
    default_factory=lambda: standardize_response("fallback", data={}, error="email test failed"),
    operation="api_alerts_test_email",
)
def alerts_test_email(payload: AlertTestRequest) -> dict[str, Any]:
    test_alert = alert_engine.send_email_test(payload)
    return standardize_response(
        "success",
        data={"test_alert": test_alert},
        metadata={"tenant_id": payload.tenant_id or "default"},
        error=None,
    )


@router.post("/kill-switch/approve")
@safe_execution(
    default_factory=lambda: standardize_response("fallback", data={}, error="kill switch approval failed"),
    operation="api_kill_switch_approve",
)
def alerts_kill_switch_approve(payload: KillSwitchApproveRequest) -> dict[str, Any]:
    approval = alert_engine.kill_switch_engine.approve(payload)
    return standardize_response(
        "success",
        data={"approval": approval},
        metadata={"alert_id": payload.alert_id},
        error=None,
    )