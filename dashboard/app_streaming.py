"""
SentinelAI Enterprise SOC Dashboard - Real-Time Streaming Version
==================================================================

Real-time Windows behavioral security with WebSocket streaming.
Receives events from Kafka via WebSocket server (no polling).

This version replaces:
- File polling with WebSocket real-time push
- Aggressive refresh (5s) with event-driven updates
- Full page reloads with incremental updates

Architecture:
Kafka → KafkaConsumer → EventBuffer → WebSocket Server → Dashboard (WebSocket client)
"""

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from __future__ import annotations

from collections import Counter, deque
from datetime import datetime, timedelta
import asyncio
import json

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from collector.storage import load_json, read_jsonl
from dashboard.data_buffer import get_buffer
from sentinel_config import CONFIG

# Page configuration
st.set_page_config(
    page_title="SentinelAI SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Dark SOC theme CSS
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
        .success-card {
            background: rgba(50, 150, 50, 0.1);
            border-left: 4px solid #44ff44;
            padding: 12px;
            margin: 8px 0;
            border-radius: 4px;
        }
        .streaming-badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 20px;
            background: #1a5f4a;
            border: 1px solid #44ff44;
            color: #44ff44;
            font-size: 0.8rem;
            font-weight: bold;
            margin-left: 10px;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


# ===== STREAMING DATA LAYER =====
# Use EventBuffer instead of file polling
# Events arrive via WebSocket from Kafka consumer

@st.cache_data(ttl=60, show_spinner=False)
def load_baselines_cached() -> dict:
    """Cached baseline loading."""
    try:
        return load_json(CONFIG.baseline_store, {})
    except Exception:
        return {}

@st.cache_data(ttl=60, show_spinner=False)
def load_model_metadata_cached() -> dict:
    """Cached model metadata loading."""
    try:
        return load_json(CONFIG.model_metadata_store, {})
    except Exception:
        return {}


# ===== REAL-TIME EVENT STREAMING INITIALIZATION =====
if "event_buffer_initialized" not in st.session_state:
    st.session_state.event_buffer_initialized = True
    st.session_state.streamed_events = deque(maxlen=5000)
    st.session_state.streamed_incidents = deque(maxlen=500)
    st.session_state.last_update_time = datetime.utcnow()

# Get global EventBuffer (populated by Kafka consumer + WebSocket server)
buffer = get_buffer()

# Fetch events from buffer (these arrive in real-time from Kafka/WebSocket)
current_events = buffer.get_events(tenant_id="default", limit=500)
current_incidents = buffer.get_incidents(tenant_id="default", limit=500)

# Update session state with new events
for event in current_events:
    st.session_state.streamed_events.append(event)

for incident in current_incidents:
    st.session_state.streamed_incidents.append(incident)

# Convert to DataFrames for analysis
event_df = pd.DataFrame(list(st.session_state.streamed_events)) if st.session_state.streamed_events else pd.DataFrame()
incident_df = pd.DataFrame(list(st.session_state.streamed_incidents)) if st.session_state.streamed_incidents else pd.DataFrame()

# Parse timestamps if available
if not event_df.empty and "timestamp" in event_df.columns:
    event_df["timestamp"] = pd.to_datetime(event_df["timestamp"], errors="coerce")

if not incident_df.empty and "timestamp" in incident_df.columns:
    incident_df["timestamp"] = pd.to_datetime(incident_df["timestamp"], errors="coerce")


def severity_color(severity: str) -> str:
    """Map severity to color."""
    colors = {
        "critical": "#ff3333",
        "high": "#ff9900",
        "medium": "#ffcc00",
        "low": "#33cc33",
    }
    return colors.get(severity, "#cccccc")


def severity_badge(severity: str) -> str:
    """HTML badge for severity."""
    color = severity_color(severity)
    return f'<span style="background:{color}; color:white; padding:3px 8px; border-radius:4px; font-weight:bold; font-size:0.85rem;">{severity.upper()}</span>'


# ===== CHART GENERATION CACHING =====
@st.cache_data(ttl=30, show_spinner=False)
def create_risk_trend_chart(incidents_df: pd.DataFrame):
    """Cached risk score trend chart."""
    if incidents_df.empty or "timestamp" not in incidents_df.columns:
        return None
    
    timeline_data = incidents_df[["timestamp", "risk_score", "severity"]].tail(100).sort_values("timestamp")
    
    fig = go.Figure()
    for severity_level in ["critical", "high", "medium", "low"]:
        mask = timeline_data["severity"] == severity_level
        if mask.any():
            fig.add_trace(go.Scatter(
                x=timeline_data[mask]["timestamp"],
                y=timeline_data[mask]["risk_score"],
                mode="markers+lines",
                name=severity_level.upper(),
                marker=dict(size=8, color=severity_color(severity_level))
            ))
    
    fig.update_layout(
        template="plotly_dark",
        height=320,
        title="Risk Scores Over Time (Real-Time Streaming)",
        xaxis_title="Time",
        yaxis_title="Risk Score",
        hovermode="x unified"
    )
    return fig


@st.cache_data(ttl=30, show_spinner=False)
def create_severity_pie_chart(incidents_df: pd.DataFrame):
    """Cached severity distribution pie chart."""
    if incidents_df.empty:
        return None
    
    severity_dist = incidents_df["severity"].value_counts()
    fig = px.pie(
        values=severity_dist.values,
        names=severity_dist.index,
        color=severity_dist.index,
        color_discrete_map={
            "critical": "#ff3333",
            "high": "#ff9900",
            "medium": "#ffcc00",
            "low": "#33cc33",
        }
    )
    fig.update_layout(template="plotly_dark", height=320)
    return fig


# ===== HEADER =====
col1, col2, col3 = st.columns([3, 1, 1])
with col1:
    st.title("🛡️ SentinelAI")
    st.caption("Enterprise Endpoint Detection & Response (EDR) with AI-Powered Behavioral Analytics")
with col3:
    # Real-time streaming status
    buffer_stats = buffer.get_stats()
    status = "🟢 LIVE STREAMING" if buffer_stats["current_subscribers"] > 0 else "🟡 BUFFERED"
    st.markdown(
        f'<span class="streaming-badge">{status}</span>',
        unsafe_allow_html=True
    )
with col2:
    model_metadata = load_model_metadata_cached()
    if isinstance(model_metadata, dict):
        status = model_metadata.get("status", "unknown")
        status_color = "🟢" if status == "trained" else "🟡"
        st.metric("ML Status", status_color, model_metadata.get("feature_count", 0))


# ===== DASHBOARD METRICS =====
st.markdown("### 📊 Real-Time Sentinel Metrics (Streaming)")

metric_cols = st.columns(5)

# Event count
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

# Threat summary
severity_counts = Counter(incident_df["severity"]) if not incident_df.empty else Counter()
critical_count = severity_counts.get("critical", 0)
high_count = severity_counts.get("high", 0)
threats = critical_count + high_count

with metric_cols[1]:
    color = "🔴" if threats > 0 else "🟢"
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">Active Threats</div>
            <div class="metric-value">{color} {threats}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

# Critical alerts
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

# Buffer status
with metric_cols[3]:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">Buffer Events</div>
            <div class="metric-value">{buffer_stats.get('total_events', 0):,}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

# Subscribers
with metric_cols[4]:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">WebSocket Clients</div>
            <div class="metric-value">{buffer_stats.get('current_subscribers', 0)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ===== MAIN DASHBOARD =====
tab1, tab2, tab3, tab4, tab5 = st.tabs(
    ["🔴 Threats", "📈 Timeline", "👤 Users", "🔍 Details", "⚙️ System"]
)

# ===== TAB 1: ACTIVE THREATS =====
with tab1:
    st.subheader("Critical & High Risk Incidents (Real-Time)")
    
    if incident_df.empty:
        st.success("✅ No threats detected")
    else:
        threat_df = incident_df[incident_df["severity"].isin(["critical", "high"])]
        
        if threat_df.empty:
            st.info("No high-risk incidents in recent window")
        else:
            for _, row in threat_df.sort_values("risk_score", ascending=False).head(20).iterrows():
                timestamp_str = str(row.get("timestamp", ""))[:19]
                user_str = str(row.get("user", "unknown"))
                event_type = str(row.get("event_type", "unknown"))
                risk_score = row.get("risk_score", 0)
                story = str(row.get("story", ""))
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

# ===== TAB 2: TIMELINE & TRENDS =====
with tab2:
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Risk Score Trend (Real-Time Stream)")
        risk_fig = create_risk_trend_chart(incident_df)
        if risk_fig:
            st.plotly_chart(risk_fig, use_container_width=True, key="risk_trend")
        else:
            st.info("No data yet")
    
    with col2:
        st.subheader("Severity Distribution")
        severity_fig = create_severity_pie_chart(incident_df)
        if severity_fig:
            st.plotly_chart(severity_fig, use_container_width=True, key="severity_pie")
        else:
            st.info("No data yet")
    
    st.subheader("Recent Activity Log (Streaming)")
    if event_df.empty:
        st.info("No telemetry collected yet")
    else:
        display_cols = [c for c in ["timestamp", "source", "event_type", "user", "message"] if c in event_df.columns]
        st.dataframe(
            event_df[display_cols].tail(50),
            use_container_width=True,
            hide_index=True
        )

# ===== TAB 3: USER PROFILES =====
with tab3:
    st.subheader("UEBA User Baselines")
    
    baselines = load_baselines_cached()
    
    if not baselines:
        st.info("Baselines will appear after telemetry collection")
    else:
        selected_user = st.selectbox("Select user:", sorted(baselines.keys()))
        profile = baselines[selected_user]
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Login Time Pattern")
            if profile.get("login_time_distribution"):
                login_dist = profile["login_time_distribution"]
                fig = px.bar(
                    x=[int(h) for h in login_dist.keys()],
                    y=list(login_dist.values()),
                    labels={"x": "Hour of Day", "y": "Frequency"}
                )
                fig.update_layout(template="plotly_dark", height=280)
                st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("Devices & Locations")
            devices = profile.get("device_fingerprint", [])
            st.write(f"**Devices:** {len(devices)}")
            for device in devices[:5]:
                st.caption(f"📍 {device}")
        
        stats_col1, stats_col2, stats_col3 = st.columns(3)
        with stats_col1:
            st.metric("Total Logins", profile.get("total_logins", 0))
        with stats_col2:
            st.metric("Failed Logins", profile.get("failed_logins", 0))
        with stats_col3:
            st.metric("Auth Methods", len(profile.get("auth_methods", [])))

# ===== TAB 4: EVENT DETAILS =====
with tab4:
    st.subheader("Detailed Incident Analysis")
    
    if incident_df.empty:
        st.info("No incidents to display")
    else:
        selected_idx = st.selectbox(
            "Select incident:",
            range(len(incident_df)),
            format_func=lambda i: f"{incident_df.iloc[i].get('event_type', '?')} - {str(incident_df.iloc[i].get('timestamp', ''))[:19]}"
        )
        
        incident = incident_df.iloc[selected_idx].to_dict()
        st.json(incident)

# ===== TAB 5: SYSTEM STATUS =====
with tab5:
    st.subheader("Model & System Status")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("ML Model Info")
        model_metadata = load_model_metadata_cached()
        if isinstance(model_metadata, dict):
            st.write(f"**Status:** {model_metadata.get('status', 'unknown')}")
            st.write(f"**Data Source:** {model_metadata.get('data_source', 'unknown')}")
            st.write(f"**Training Samples:** {model_metadata.get('training_samples', 0)}")
            st.write(f"**Features:** {model_metadata.get('feature_count', 0)}")
            
            perf = model_metadata.get("model_performance", {})
            if isinstance(perf, dict):
                st.write("**Performance Metrics:**")
                st.write(f"  - Accuracy: {perf.get('accuracy', 0):.4f}")
                st.write(f"  - Precision: {perf.get('precision', 0):.4f}")
                st.write(f"  - Recall: {perf.get('recall', 0):.4f}")
                st.write(f"  - F1-Score: {perf.get('f1', 0):.4f}")
    
    with col2:
        st.subheader("Real-Time Streaming Status")
        buffer_stats = buffer.get_stats()
        st.write(f"**Total Events Buffered:** {buffer_stats.get('total_events', 0)}")
        st.write(f"**Total Incidents Buffered:** {buffer_stats.get('total_incidents', 0)}")
        st.write(f"**Current WebSocket Subscribers:** {buffer_stats.get('current_subscribers', 0)}")
        st.write(f"**Last Update:** {buffer_stats.get('last_update', 'never')}")
        st.write(f"**Kafka Consumer Lag:** {buffer_stats.get('kafka_lag', 'unknown')}")
        
        st.subheader("Data Collection")
        st.write(f"**Total Events in Session:** {len(event_df)}")
        st.write(f"**Total Incidents in Session:** {len(incident_df)}")
        st.write(f"**Memory Usage:** {buffer_stats.get('memory_usage_mb', 0):.1f} MB")
    
    st.subheader("Configuration")
    st.write(f"**WebSocket Server:** {CONFIG.websocket_server_url}")
    st.write(f"**Kafka Bootstrap Servers:** {CONFIG.kafka_bootstrap_servers}")
    st.write(f"**Kafka Topic:** {CONFIG.kafka_scored_topic}")
    st.write(f"**Event Store (Fallback):** {CONFIG.event_store}")

# Footer
st.markdown("---")
st.caption(
    "🟢 SentinelAI v2.0 Real-Time Streaming | "
    "Enterprise EDR Platform | "
    "Kafka → WebSocket → Live Dashboard"
)
