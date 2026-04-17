from __future__ import annotations

import os
from collections import Counter

import pandas as pd
import plotly.express as px
import requests
import streamlit as st
from streamlit_autorefresh import st_autorefresh

from core.transformers import normalize_event, safe_dataframe_convert, safe_empty_check


API_BASE_URL = os.getenv("SENTINEL_API_BASE_URL", "http://127.0.0.1:8000")
REFRESH_MS = int(os.getenv("SENTINEL_REFRESH_MS", "15000"))

st.set_page_config(page_title="SentinelAI SOC", page_icon="S", layout="wide")
st_autorefresh(interval=REFRESH_MS, key="sentinel_refresh")

st.markdown(
    """
    <style>
        .stApp {
            background: radial-gradient(circle at top, #17324d 0%, #09111c 45%, #05080f 100%);
            color: #edf2f7;
        }
        .sentinel-card {
            background: rgba(8, 18, 30, 0.92);
            border: 1px solid rgba(95, 135, 180, 0.25);
            border-radius: 18px;
            padding: 1rem 1.2rem;
            box-shadow: 0 16px 40px rgba(0, 0, 0, 0.28);
        }
        .metric-label {
            font-size: 0.82rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: #8ca6c1;
        }
        .metric-value {
            font-size: 2rem;
            font-weight: 700;
            color: #f5fbff;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


def api_get(path: str, **params: object) -> dict[str, object]:
    try:
        response = requests.get(f"{API_BASE_URL}{path}", params=params, timeout=10)
        response.raise_for_status()
        payload = response.json()
        if isinstance(payload, dict):
            return payload
    except Exception as exc:
        return {"status": "error", "data": {}, "metadata": {}, "error": str(exc)}
    return {"status": "fallback", "data": {}, "metadata": {}, "error": "invalid response"}


def response_data(payload: dict[str, object]) -> dict[str, object]:
    data = payload.get("data", {})
    return data if isinstance(data, dict) else {}


def safe_series(frame: pd.DataFrame, column: str) -> pd.Series:
    if column not in frame.columns:
        return pd.Series(dtype=str)
    return frame[column]


st.title("SentinelAI Enterprise Behavioral Security and SOC Platform")
st.caption("Real-time threat detection, UEBA, network intrusion analytics, and adaptive response orchestration.")

logs_response = api_get("/logs", limit=150)
timeline_response = api_get("/attack-timeline", limit=150)
root_response = api_get("/")

if logs_response.get("error"):
    st.error(
        "Backend is unavailable or no processed data has been generated yet. "
        "Run `python -m ml.training` and start the FastAPI service."
    )
    st.stop()

records = response_data(logs_response).get("records", [])
timeline_records = response_data(timeline_response).get("records", [])
root_data = response_data(root_response)

logs_df = safe_dataframe_convert([normalize_event(record) for record in records if isinstance(record, dict)])
timeline_df = safe_dataframe_convert([normalize_event(record) for record in timeline_records if isinstance(record, dict)])

severity_counts = Counter(safe_series(timeline_df, "severity").fillna("unknown")) if not safe_empty_check(timeline_df) else Counter()
critical_count = severity_counts.get("critical", 0)
high_count = severity_counts.get("high", 0)

metric_cols = st.columns(4)
for col, label, value in [
    (metric_cols[0], "Artifacts Status", "Ready" if root_data.get("artifacts_loaded") else "Pending"),
    (metric_cols[1], "Critical Incidents", critical_count),
    (metric_cols[2], "High Risk Events", high_count),
    (metric_cols[3], "Observed Events", len(records) if isinstance(records, list) else 0),
]:
    with col:
        st.markdown(
            f"<div class='sentinel-card'><div class='metric-label'>{label}</div><div class='metric-value'>{value}</div></div>",
            unsafe_allow_html=True,
        )

left, right = st.columns([1.5, 1.0])

with left:
    st.subheader("Real-time Threat Feed")
    if safe_empty_check(timeline_df):
        st.info("No analyzed incidents have been recorded yet. POST events to `/analyze` to populate the threat feed.")
    else:
        columns = [column for column in ["event_id", "user", "risk_score", "severity", "response_action", "incident_story"] if column in timeline_df.columns]
        st.dataframe(timeline_df[columns].tail(20), use_container_width=True, hide_index=True)

    st.subheader("Risk Score Analytics")
    if safe_empty_check(timeline_df) or "risk_score" not in timeline_df.columns:
        st.info("Risk analytics will appear after events are analyzed by the API.")
    else:
        x_axis = "analyzed_at" if "analyzed_at" in timeline_df.columns else "timestamp"
        fig = px.line(
            timeline_df.tail(50),
            x=x_axis,
            y="risk_score",
            color="severity" if "severity" in timeline_df.columns else None,
            color_discrete_map={
                "low": "#2ecc71",
                "medium": "#f1c40f",
                "high": "#e67e22",
                "critical": "#e74c3c",
            },
            markers=True,
        )
        fig.update_layout(template="plotly_dark", height=350, margin=dict(l=20, r=20, t=20, b=20))
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Attack Timeline Viewer")
    if safe_empty_check(timeline_df):
        st.info("Incident forensics are empty until analyzed events are stored.")
    else:
        timeline_cols = [column for column in ["timestamp", "user", "severity", "triggered_rules", "incident_story"] if column in timeline_df.columns]
        st.dataframe(timeline_df[timeline_cols].tail(25), use_container_width=True, hide_index=True)

    st.subheader("Network Activity Map")
    if safe_empty_check(logs_df):
        st.info("No processed network or authentication logs are available.")
    else:
        if {"src_ip", "dst_ip"}.issubset(logs_df.columns):
            flow_counts = (
                logs_df.dropna(subset=["src_ip", "dst_ip"])
                .groupby(["src_ip", "dst_ip"])
                .size()
                .reset_index(name="count")
                .sort_values("count", ascending=False)
                .head(25)
            )
            fig = px.scatter(flow_counts, x="src_ip", y="dst_ip", size="count", color="count", color_continuous_scale="Turbo")
            fig.update_layout(template="plotly_dark", height=320, margin=dict(l=20, r=20, t=20, b=20))
            st.plotly_chart(fig, use_container_width=True)
        elif {"source_host", "destination_host"}.issubset(logs_df.columns):
            host_counts = (
                logs_df.dropna(subset=["source_host", "destination_host"])
                .groupby(["source_host", "destination_host"])
                .size()
                .reset_index(name="count")
                .sort_values("count", ascending=False)
                .head(25)
            )
            fig = px.scatter(host_counts, x="source_host", y="destination_host", size="count", color="count", color_continuous_scale="Turbo")
            fig.update_layout(template="plotly_dark", height=320, margin=dict(l=20, r=20, t=20, b=20))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("The current processed logs do not contain network map fields yet.")

with right:
    st.subheader("User Behavior Profiles")
    if safe_empty_check(logs_df) or "user" not in logs_df.columns:
        st.info("User profiles appear after LANL authentication data is ingested.")
    else:
        user_ids = sorted([user for user in logs_df["user"].dropna().astype(str).unique().tolist() if user])
        if user_ids:
            selected_user = st.selectbox("Select user", user_ids, key="selected_user")
            profile_response = api_get("/user-profile", user_id=selected_user)
            if profile_response.get("error") or profile_response.get("detail"):
                st.warning(str(profile_response.get("detail", profile_response.get("error"))))
            else:
                st.json(response_data(profile_response))
        else:
            st.info("No user identifiers are present in the current log slice.")

    st.subheader("AI Threat Explanation Panel")
    if safe_empty_check(timeline_df):
        st.info("Threat explanations will appear as incidents are analyzed.")
    else:
        latest = timeline_df.tail(1).to_dict(orient="records")[0]
        st.markdown(f"**Severity:** {str(latest.get('severity', 'unknown')).upper()}")
        st.markdown(f"**Risk Score:** {latest.get('risk_score', 0)}")
        st.write(latest.get("explanation", "No explanation captured."))
        st.write(latest.get("incident_story", "No incident story captured."))

    st.subheader("File Access Monitoring Panel")
    if safe_empty_check(timeline_df) or "triggered_rules" not in timeline_df.columns:
        st.info("Sensitive file access indicators will appear here when flagged in analyzed events.")
    else:
        file_events = timeline_df[timeline_df["triggered_rules"].astype(str).str.contains("sensitive_file_access", na=False)]
        st.dataframe(file_events.tail(10), use_container_width=True, hide_index=True)

    st.subheader("Insider Threat Alerts")
    if safe_empty_check(timeline_df) or "triggered_rules" not in timeline_df.columns:
        st.info("No insider threat alerts detected.")
    else:
        insider = timeline_df[
            timeline_df["triggered_rules"].astype(str).str.contains(
                "bulk_download|privilege_escalation|behavior_unusual_location|behavior_rare_action",
                na=False,
            )
        ]
        st.dataframe(insider.tail(10), use_container_width=True, hide_index=True)
