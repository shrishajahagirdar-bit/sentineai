from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pandas as pd

from core.safe_wrapper import log_health_event
from core.schema import CanonicalEvent, MLOutputSchema, StandardResponse, UIDataSchema
from core.validator import validate_model


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_empty_check(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, pd.DataFrame):
        return value.empty
    if isinstance(value, (list, dict, tuple, set, str)):
        return len(value) == 0
    return False


def safe_dataframe_convert(data: Any, columns: list[str] | None = None) -> pd.DataFrame:
    if isinstance(data, pd.DataFrame):
        frame = data.copy()
    elif isinstance(data, list):
        frame = pd.DataFrame(data)
    elif isinstance(data, dict):
        if "records" in data and isinstance(data["records"], list):
            frame = pd.DataFrame(data["records"])
        else:
            frame = pd.DataFrame([data])
    else:
        frame = pd.DataFrame()

    if columns:
        for column in columns:
            if column not in frame.columns:
                frame[column] = None
        frame = frame[columns]

    return frame


def dataframe_to_records(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, pd.DataFrame):
        if data.empty:
            return []
        return data.fillna("").to_dict(orient="records")
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        if "records" in data and isinstance(data["records"], list):
            return [item for item in data["records"] if isinstance(item, dict)]
        return [data]
    return []


def normalize_ml_output(raw_output: Any, *, user: str = "unknown") -> dict[str, Any]:
    if isinstance(raw_output, tuple):
        probability = raw_output[0] if len(raw_output) > 0 else 0.0
        anomaly = raw_output[1] if len(raw_output) > 1 else 0.0
        payload = {
            "user": user,
            "risk_score": float(probability or 0.0),
            "prediction": "anomaly" if float(probability or 0.0) >= 0.5 else "normal",
            "anomaly_score": float(anomaly or 0.0),
            "timestamp": _utc_now_iso(),
            "status": "success",
            "message": "ml output normalized",
        }
    elif isinstance(raw_output, dict):
        payload = {
            "user": raw_output.get("user", raw_output.get("user_id", user)),
            "risk_score": raw_output.get("risk_score", raw_output.get("supervised_probability", raw_output.get("ml_score", 0.0))),
            "prediction": raw_output.get("prediction", raw_output.get("ml_prediction", "unknown")),
            "anomaly_score": raw_output.get("anomaly_score", 0.0),
            "timestamp": raw_output.get("timestamp", _utc_now_iso()),
            "status": raw_output.get("status", "success"),
            "message": raw_output.get("message", "ml output normalized"),
            "metadata": raw_output.get("metadata", {}),
        }
    else:
        payload = {}

    fallback = {
        "user": user,
        "risk_score": 0.0,
        "prediction": "unknown",
        "anomaly_score": 0.0,
        "timestamp": _utc_now_iso(),
        "status": "safe_fallback",
        "message": "data unavailable",
        "metadata": {},
    }
    return validate_model(payload, MLOutputSchema, fallback=fallback)


def normalize_event(raw_event: Any) -> dict[str, Any]:
    fallback = {
        "event_id": "fallback-event",
        "timestamp": _utc_now_iso(),
        "hostname": "unknown",
        "source": "middleware",
        "event_type": "fallback",
        "severity": "low",
        "raw_log": "data unavailable",
        "parsed_fields": {},
        "ml_score": 0.0,
        "ml_prediction": "unknown",
        "metadata": {},
        "user": "unknown",
        "message": "data unavailable",
        "risk_score": 0.0,
        "anomaly_score": 0.0,
        "status": "safe_fallback",
    }
    return validate_model(raw_event, CanonicalEvent, fallback=fallback)


def normalize_ui_payload(raw_payload: Any) -> dict[str, Any]:
    payload = raw_payload if isinstance(raw_payload, dict) else {}
    fallback = {
        "metrics": {},
        "alerts": [],
        "logs": [],
        "risk_trend": [],
        "status": "safe_fallback",
        "message": "data unavailable",
    }
    return validate_model(payload, UIDataSchema, fallback=fallback)


def standardize_response(
    status: str,
    data: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    payload = {
        "status": status if status in {"success", "error", "fallback"} else "fallback",
        "data": data or {},
        "metadata": metadata or {},
        "error": error,
    }
    return validate_model(payload, StandardResponse, fallback={"status": "fallback", "data": {}, "metadata": {}, "error": error})


def normalize_record_list(raw_records: Any) -> list[dict[str, Any]]:
    records = dataframe_to_records(raw_records)
    normalized: list[dict[str, Any]] = []
    for record in records:
        try:
            normalized.append(normalize_event(record))
        except Exception as exc:
            log_health_event(
                "error",
                "normalize_record_list",
                "Record normalization failed; row skipped.",
                context={"error": str(exc)},
            )
    return normalized
