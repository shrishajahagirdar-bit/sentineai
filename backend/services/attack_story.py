from __future__ import annotations


def build_incident_story(
    user_id: str | None,
    action: str | None,
    triggered_rules: list[str],
    response_action: str,
    severity: str,
) -> str:
    subject = f"User {user_id}" if user_id else "Observed entity"
    action_text = action or "performed an anomalous action"

    if triggered_rules:
        joined_rules = ", ".join(triggered_rules)
        return (
            f"{subject} {action_text}, triggering {joined_rules}. "
            f"The incident was classified as {severity} severity and the recommended response is {response_action.lower()}."
        )

    return (
        f"{subject} {action_text}. Behavioral and anomaly models marked the activity as {severity} severity, "
        f"so the recommended response is {response_action.lower()}."
    )

