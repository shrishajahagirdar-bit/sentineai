from __future__ import annotations


def build_attack_story(event: dict, triggers: list[str], action: str, severity: str) -> str:
    process_name = event.get("process_name") or event.get("event_type") or "activity"
    file_path = event.get("path")
    remote_ip = event.get("remote_ip")

    pieces = [f"{process_name} was observed"]
    if file_path:
        pieces.append(f"touching {file_path}")
    if remote_ip:
        pieces.append(f"connecting to {remote_ip}")
    if triggers:
        pieces.append(f"with indicators including {', '.join(triggers)}")

    return (
        " ".join(pieces)
        + f", leading to a {severity} risk classification. Recommended response: {action.lower()}."
    )

