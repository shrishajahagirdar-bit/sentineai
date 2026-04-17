from __future__ import annotations

import asyncio
from datetime import datetime
import json
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import StreamingResponse

from backend.config import settings
from backend.models.schemas import AnalyzeRequest, FeedbackRequest, UserProfileResponse
from backend.services.data_access import (
    append_jsonl,
    dataframe_records,
    load_auth_events,
    load_jsonl_events,
    load_network_events,
    load_profiles,
)
from backend.services.model_registry import ModelRegistry
from backend.services.risk_engine import RiskEngine
from backend.services.ueba import UebaService, summarize_risk_factors
from core.safe_wrapper import safe_execution
from core.transformers import normalize_event, standardize_response


app = FastAPI(title="SentinelAI", version="1.0.0")
model_registry = ModelRegistry()
ueba_service = UebaService()
risk_engine = RiskEngine(model_registry, ueba_service)


@app.get("/")
def root() -> dict[str, Any]:
    return standardize_response(
        "success",
        data={
            "application": settings.app_name,
            "system_status": "ready" if model_registry.ready else "awaiting_training",
            "artifacts_loaded": model_registry.ready,
        },
        metadata={"service": "api"},
        error=None,
    )


@app.post("/analyze")
@safe_execution(
    default_factory=lambda: standardize_response(
        "fallback",
        data={"status": "safe_fallback", "message": "data unavailable", "risk_score": 0},
        error="analysis failed",
    ),
    operation="api_analyze",
)
def analyze(request: AnalyzeRequest) -> dict[str, Any]:
    result = risk_engine.score_event(request)
    normalized_record = normalize_event(
        {
            **request.model_dump(),
            **result.as_dict(),
            "analyzed_at": datetime.utcnow().isoformat(),
        }
    )
    append_jsonl(settings.timeline_file, normalized_record)
    return standardize_response(
        "success",
        data=normalized_record,
        metadata={"service": "risk_engine"},
        error=None,
    )


@app.get("/logs")
@safe_execution(
    default_factory=lambda: standardize_response("fallback", data={"records": []}, error="log retrieval failed"),
    operation="api_logs",
)
def logs(limit: int = Query(default=50, le=500), stream: bool = False) -> Any:
    network_df = load_network_events(limit)
    auth_df = load_auth_events(limit)

    combined: list[dict[str, Any]] = []
    combined.extend(dataframe_records(network_df.tail(limit)))
    combined.extend(dataframe_records(auth_df.tail(limit)))
    combined = [normalize_event(record) for record in combined[-limit:]]

    if not stream:
        return standardize_response(
            "success",
            data={"records": combined},
            metadata={"count": len(combined), "limit": limit},
            error=None,
        )

    async def event_generator() -> Any:
        for record in combined:
            yield f"data: {json.dumps(record, default=str)}\n\n"
            await asyncio.sleep(0.1)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/user-profile")
@safe_execution(
    default_factory=lambda: standardize_response("fallback", data={}, error="profile retrieval failed"),
    operation="api_user_profile",
)
def user_profile(user_id: str) -> dict[str, Any]:
    profiles = load_profiles()
    if user_id not in profiles:
        raise HTTPException(status_code=404, detail=f"No UEBA profile found for user '{user_id}'.")

    payload = profiles[user_id]
    response = UserProfileResponse(
        user_id=user_id,
        login_time_distribution=payload.get("login_time_distribution", {}),
        location_history=payload.get("location_history", []),
        device_fingerprint=payload.get("device_fingerprint", []),
        activity_sequence_model=payload.get("activity_sequence_model", []),
        risk_factors=summarize_risk_factors(payload),
    )
    return standardize_response(
        "success",
        data=response.model_dump(),
        metadata={"service": "ueba"},
        error=None,
    )


@app.get("/attack-timeline")
@safe_execution(
    default_factory=lambda: standardize_response("fallback", data={"records": []}, error="timeline retrieval failed"),
    operation="api_attack_timeline",
)
def attack_timeline(user_id: str | None = None, event_id: str | None = None, limit: int = 100) -> dict[str, Any]:
    records = load_jsonl_events(settings.timeline_file, limit=limit)

    if user_id:
        records = [record for record in records if record.get("user") == user_id or record.get("user_id") == user_id]
    if event_id:
        records = [record for record in records if record.get("event_id") == event_id]

    return standardize_response(
        "success",
        data={"records": records},
        metadata={"count": len(records), "limit": limit},
        error=None,
    )


@app.post("/feedback")
@safe_execution(
    default_factory=lambda: standardize_response("fallback", data={}, error="feedback storage failed"),
    operation="api_feedback",
)
def feedback(payload: FeedbackRequest) -> dict[str, Any]:
    append_jsonl(
        settings.feedback_file,
        {
            **payload.model_dump(),
            "timestamp": (payload.timestamp or datetime.utcnow()).isoformat(),
        },
    )
    return standardize_response(
        "success",
        data={"stored": True},
        metadata={"event_id": payload.event_id},
        error=None,
    )
