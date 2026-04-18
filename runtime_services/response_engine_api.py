from __future__ import annotations

from fastapi import FastAPI, Response
from pydantic import BaseModel

from observability.metrics import export_prometheus, SERVICE_HEALTH
from response_engine.engine import ResponseEngine


class ActionRequest(BaseModel):
    tenant_id: str
    requested_by: str
    reason: str
    action_type: str
    target: str
    approved: bool = False


app = FastAPI(title="SentinelAI Response Engine", version="0.1.0")
engine = ResponseEngine(mode="monitor")


@app.get("/")
def root() -> dict[str, str]:
    return {"service": "response-engine", "status": "ok"}


@app.get("/health")
def health() -> dict[str, str]:
    SERVICE_HEALTH.labels(service="response-engine").set(1)
    return {"service": "response-engine", "status": "healthy"}


@app.get("/metrics")
def metrics() -> Response:
    return Response(content=export_prometheus(), media_type="text/plain; version=0.0.4")


@app.post("/actions")
def create_action(payload: ActionRequest) -> dict:
    action = engine.request_action(
        tenant_id=payload.tenant_id,
        requested_by=payload.requested_by,
        reason=payload.reason,
        action_type=payload.action_type,
        target=payload.target,
        approved=payload.approved,
    )
    return action.to_dict()
