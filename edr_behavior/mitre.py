from __future__ import annotations


MITRE_EVENT_MAP = {
    "login_failure": {"technique": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "login": {"technique": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"},
    "process_create": {"technique": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "network_connection": {"technique": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
    "privilege_change": {"technique": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    "registry_change": {"technique": "T1112", "name": "Modify Registry", "tactic": "Defense Evasion"},
    "file_modify": {"technique": "T1547", "name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
}


def map_to_mitre(event: dict) -> dict[str, str]:
    return MITRE_EVENT_MAP.get(str(event.get("event_type", "")).lower(), {})
