"""
SentinelAI Enterprise SOC Dashboard
===================================

Real-time Windows behavioral security with ML + UEBA integration.
"""

from __future__ import annotations

from collections import Counter

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from streamlit_autorefresh import st_autorefresh

from collector.storage import load_json, read_jsonl
from core.transformers import normalize_event, safe_dataframe_convert, safe_empty_check
from sentinel_config import CONFIG


st.set_page_config(
    page_title="SentinelAI SOC",
    page_icon="S",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st_autorefresh(interval=CONFIG.dashboard_refresh_ms, key="sentinel_dashboard")

st.markdown(
    """
    <style>
        .stApp {
            background: linear-gradient(135deg, #0f1620 0%, #1a2332 50%, #0d0f17 100%);
            color: #e0e6ed;
        }
        .metric-card {
            background: linear-gradient(135deg, rgba(30, 60, 90, 0.4), rgba(20, 40, 70, 0.4));
            border: 1px solid rgba(100, 150, 200, 0.3);
            border-radius: 12px;
            padding: 20px;
            margin: 10px 0;
        }
        .metric-value {
            font-size: 2.5rem;
            font-weight: bold;
            color: #00d4ff;
        }
        .metric-label {
            font-size: 0.9rem;
            color: #a0b0c0;
            text-transform: uppercase;
            letter-spacing: 0.1em;
        }
        .alert-card {
            background: rgba(200, 50, 50, 0.1);
            border-left: 4px solid #ff4444;
            padding: 12px;
            margin: 8px 0;
            border-radius: 4px;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


def severity_color(severity: str) -> str:
    colors = {
        "critical": "#ff3333",
        "high": "#ff9900",
        "medium": "#ffcc00",
        "low": "#33cc33",
    }
    return colors.get(str(severity).lower(), "#cccccc")


def severity_badge(severity: str) -> str:
    color = severity_color(severity)
    return f'<span style="background:{color}; color:white; padding:3px 8px; border-radius:4px; font-weight:bold; font-size:0.85rem;">{str(severity).upper()}</span>'


events = read_jsonl(CONFIG.event_store, limit=500)
incidents = read_jsonl(CONFIG.incident_store, limit=500)
baselines = load_json(CONFIG.baseline_store, {})
model_metadata = load_json(CONFIG.model_metadata_store, {})

event_df = safe_dataframe_convert([normalize_event(event) for event in events if isinstance(event, dict)])
incident_df = safe_dataframe_convert([normalize_event(event) for event in incidents if isinstance(event, dict)])
baselines = baselines if isinstance(baselines, dict) else {}
model_metadata = model_metadata if isinstance(model_metadata, dict) else {}

if not safe_empty_check(event_df) and "timestamp" in event_df.columns:
    event_df["timestamp"] = pd.to_datetime(event_df["timestamp"], errors="coerce")

if not safe_empty_check(incident_df) and "timestamp" in incident_df.columns:
    incident_df["timestamp"] = pd.to_datetime(incident_df["timestamp"], errors="coerce")

col1, col2 = st.columns([3, 1])
with col1:
    st.title("SentinelAI")
    st.caption("Enterprise Endpoint Detection & Response (EDR) with AI-Powered Behavioral Analytics")
with col2:
    if not safe_empty_check(model_metadata):
        status = model_metadata.get("status", "unknown")
        st.metric("ML Status", status, model_metadata.get("feature_count", 0))

st.markdown("### Real-Time Sentinel Metrics")

metric_cols = st.columns(5)
severity_counts = Counter(incident_df["severity"]) if not safe_empty_check(incident_df) and "severity" in incident_df.columns else Counter()
critical_count = severity_counts.get("critical", 0)
high_count = severity_counts.get("high", 0)
threats = critical_count + high_count

with metric_cols[0]:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">Telemetry Events</div>
            <div class="metric-value">{len(event_df):,}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with metric_cols[1]:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">Active Threats</div>
            <div class="metric-value">{threats}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with metric_cols[2]:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">Critical Alerts</div>
            <div class="metric-value" style="color: #ff3333;">{critical_count}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with metric_cols[3]:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">Users Profiled</div>
            <div class="metric-value">{len(baselines)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with metric_cols[4]:
    accuracy = "N/A"
    perf = model_metadata.get("model_performance", {})
    if isinstance(perf, dict):
        acc = perf.get("accuracy", 0)
        if isinstance(acc, (int, float)):
            accuracy = f"{acc * 100:.0f}%"
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">ML Accuracy</div>
            <div class="metric-value">{accuracy}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

tab1, tab2, tab3, tab4, tab5 = st.tabs(["Threats", "Timeline", "Users", "Details", "System"])

with tab1:
    st.subheader("Critical & High Risk Incidents")
    if safe_empty_check(incident_df):
        st.success("No threats detected")
    else:
        threat_df = incident_df[incident_df["severity"].isin(["critical", "high"])] if "severity" in incident_df.columns else incident_df.iloc[0:0]
        if safe_empty_check(threat_df):
            st.info("No high-risk incidents in recent window")
        else:
            for _, row in threat_df.sort_values("risk_score", ascending=False).head(20).iterrows():
                timestamp_str = str(row.get("timestamp", ""))[:19]
                user_str = str(row.get("user", "unknown"))
                event_type = str(row.get("event_type", "unknown"))
                risk_score = float(row.get("risk_score", 0) or 0)
                story = str(row.get("story", row.get("incident_story", "")))
                severity = str(row.get("severity", "unknown"))
                st.markdown(
                    f"""
                    <div class="alert-card">
                        <strong>{severity_badge(severity)} {event_type.upper()}</strong><br/>
                        User: <code>{user_str}</code> | Score: <strong>{risk_score:.1f}/100</strong> | Time: {timestamp_str}<br/>
                        <em>{story}</em>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

with tab2:
    left_col, right_col = st.columns(2)

    with left_col:
        st.subheader("Risk Score Trend")
        if safe_empty_check(incident_df) or "timestamp" not in incident_df.columns or "risk_score" not in incident_df.columns:
            st.info("No data yet")
        else:
            timeline_data = incident_df[["timestamp", "risk_score", "severity"]].tail(100).sort_values("timestamp")
            fig = go.Figure()
            for severity_level in ["critical", "high", "medium", "low"]:
                mask = timeline_data["severity"] == severity_level
                if mask.any():
                    fig.add_trace(
                        go.Scatter(
                            x=timeline_data[mask]["timestamp"],
                            y=timeline_data[mask]["risk_score"],
                            mode="markers+lines",
                            name=severity_level.upper(),
                            marker=dict(size=8, color=severity_color(severity_level)),
                        )
                    )
            fig.update_layout(template="plotly_dark", height=320, title="Risk Scores Over Time", xaxis_title="Time", yaxis_title="Risk Score", hovermode="x unified")
            st.plotly_chart(fig, use_container_width=True)

    with right_col:
        st.subheader("Severity Distribution")
        if safe_empty_check(incident_df) or "severity" not in incident_df.columns:
            st.info("No data yet")
        else:
            severity_dist = incident_df["severity"].value_counts()
            fig = px.pie(
                values=severity_dist.values,
                names=severity_dist.index,
                color=severity_dist.index,
                color_discrete_map={
                    "critical": "#ff3333",
                    "high": "#ff9900",
                    "medium": "#ffcc00",
                    "low": "#33cc33",
                },
            )
            fig.update_layout(template="plotly_dark", height=320)
            st.plotly_chart(fig, use_container_width=True)

    st.subheader("Recent Activity Log")
    if safe_empty_check(event_df):
        st.info("No telemetry collected yet")
    else:
        display_cols = [c for c in ["timestamp", "source", "event_type", "user", "message"] if c in event_df.columns]
        st.dataframe(event_df[display_cols].tail(50), use_container_width=True, hide_index=True)

with tab3:
    st.subheader("UEBA User Baselines")
    if not baselines:
        st.info("Baselines will appear after telemetry collection")
    else:
        selected_user = st.selectbox("Select user:", sorted(baselines.keys()))
        profile = baselines.get(selected_user, {})
        if not isinstance(profile, dict):
            profile = {}

        left_col, right_col = st.columns(2)
        with left_col:
            st.subheader("Login Time Pattern")
            login_dist = profile.get("login_time_distribution", {})
            if isinstance(login_dist, dict) and login_dist:
                fig = px.bar(x=[int(h) for h in login_dist.keys()], y=list(login_dist.values()), labels={"x": "Hour of Day", "y": "Frequency"})
                fig.update_layout(template="plotly_dark", height=280)
                st.plotly_chart(fig, use_container_width=True)

        with right_col:
            st.subheader("Devices & Locations")
            devices = profile.get("device_fingerprint", [])
            devices = devices if isinstance(devices, list) else []
            st.write(f"**Devices:** {len(devices)}")
            for device in devices[:5]:
                st.caption(str(device))

        stats_col1, stats_col2, stats_col3 = st.columns(3)
        with stats_col1:
            st.metric("Total Logins", profile.get("total_logins", 0))
        with stats_col2:
            st.metric("Failed Logins", profile.get("failed_logins", 0))
        with stats_col3:
            auth_methods = profile.get("auth_methods", [])
            st.metric("Auth Methods", len(auth_methods) if isinstance(auth_methods, list) else 0)

with tab4:
    st.subheader("Detailed Incident Analysis")
    if safe_empty_check(incident_df):
        st.info("No incidents to display")
    else:
        selected_idx = st.selectbox(
            "Select incident:",
            range(len(incident_df)),
            format_func=lambda i: f"{incident_df.iloc[i].get('event_type', '?')} - {str(incident_df.iloc[i].get('timestamp', ''))[:19]}",
        )
        st.json(incident_df.iloc[selected_idx].to_dict())

with tab5:
    st.subheader("Model & System Status")
    left_col, right_col = st.columns(2)

    with left_col:
        st.subheader("ML Model Info")
        st.write(f"**Status:** {model_metadata.get('status', 'unknown')}")
        st.write(f"**Data Source:** {model_metadata.get('data_source', 'unknown')}")
        st.write(f"**Training Samples:** {model_metadata.get('training_samples', 0)}")
        st.write(f"**Features:** {model_metadata.get('feature_count', 0)}")
        perf = model_metadata.get("model_performance", {})
        if isinstance(perf, dict) and perf:
            st.write("**Performance Metrics:**")
            st.write(f"  - Accuracy: {float(perf.get('accuracy', 0)):.4f}")
            st.write(f"  - Precision: {float(perf.get('precision', 0)):.4f}")
            st.write(f"  - Recall: {float(perf.get('recall', 0)):.4f}")
            st.write(f"  - F1-Score: {float(perf.get('f1', 0)):.4f}")

    with right_col:
        st.subheader("Data Collection")
        st.write(f"**Total Events:** {len(event_df)}")
        st.write(f"**Total Incidents:** {len(incident_df)}")
        st.write(f"**Users Tracked:** {len(baselines)}")
        if not safe_empty_check(event_df) and "timestamp" in event_df.columns:
            st.write(f"**Latest Event:** {event_df['timestamp'].max()}")

    st.subheader("Configuration")
    st.write(f"**Event Store:** {CONFIG.event_store}")
    st.write(f"**Baseline Store:** {CONFIG.baseline_store}")
    st.write(f"**Model Store:** {CONFIG.model_store}")
    st.write(f"**Polling Interval:** {CONFIG.poll_interval_seconds}s")

st.markdown("---")
st.caption("SentinelAI v1.0 | Enterprise EDR Platform | Real-time Windows Behavioral Security")
