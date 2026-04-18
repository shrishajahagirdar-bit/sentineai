from __future__ import annotations

from typing import Any


LABEL_MAP = {
    "normal": 0,
    "anomaly": 1,
}


ANOMALY_ATTACK_TYPES = {"brute_force", "ddos", "insider", "insider_threat", "privilege_escalation", "scan", "port_scan"}


def label_to_name(label: int | str | None) -> str:
    if isinstance(label, str):
        lowered = label.strip().lower()
        if lowered in LABEL_MAP:
            return lowered
    if int(label or 0) == 1:
        return "anomaly"
    return "normal"


def normalize_label(event: dict[str, Any]) -> int:
    if str(event.get("event_type", "")).strip().lower() == "normal":
        return 0
    return 1


def event_label(event: dict[str, Any]) -> int:
    explicit_label = event.get("label")
    if explicit_label in {0, 1}:
        return int(explicit_label)

    event_type = str(event.get("event_type", "")).lower()
    severity = str(event.get("severity", "low")).lower()
    attack_type = str(event.get("attack_type", event.get("metadata", {}).get("attack_type", "none"))).lower()
    risk_score = float(event.get("risk_score", event.get("ml_score", 0.0)) or 0.0)
    triggers = " ".join(str(item).lower() for item in event.get("triggers", []))

    if event_type == "anomaly":
        return 1
    if event_type == "normal":
        return 0
    if attack_type in ANOMALY_ATTACK_TYPES:
        return 1
    if severity in {"high", "critical"}:
        return 1
    if risk_score >= 0.6:
        return 1
    if any(token in triggers for token in ["failed login", "unknown process", "suspicious port", "privilege", "scan"]):
        return 1
    return 0


def attach_standard_labels(event: dict[str, Any]) -> dict[str, Any]:
    payload = dict(event)
    metadata = payload.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}

    label = event_label(payload)
    event_name = label_to_name(label)

    payload["label"] = label
    payload["ml_prediction"] = str(payload.get("ml_prediction", event_name))
    payload["metadata"] = {
        **metadata,
        "label_name": event_name,
        "attack_type": str(payload.get("attack_type", metadata.get("attack_type", "none"))),
    }
    return payload
