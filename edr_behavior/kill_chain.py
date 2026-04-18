from __future__ import annotations


KILL_CHAIN_EVENT_MAP = {
    "login_failure": "initial_access",
    "login": "initial_access",
    "process_create": "execution",
    "registry_change": "persistence",
    "file_modify": "persistence",
    "network_connection": "lateral_movement",
    "exfiltration": "exfiltration",
}


def infer_stage(event: dict) -> str:
    return KILL_CHAIN_EVENT_MAP.get(str(event.get("event_type", "")).lower(), "unknown")
