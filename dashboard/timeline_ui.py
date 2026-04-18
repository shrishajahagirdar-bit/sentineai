"""
Attack Timeline Visualization UI Component

Provides Streamlit UI for:
- Timeline replay controls (play, pause, step, jump)
- Event timeline scrubber bar
- Attack chain visualization
- Process tree expansion
- MITRE ATT&CK technique display
"""

import streamlit as st
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px

from edr_behavior.timeline_store import get_timeline_store
from edr_behavior.replay_engine import get_replay_engine, PlayState
from edr_behavior.attack_chain_correlator import get_correlator


def initialize_timeline_session_state():
    """Initialize session state for timeline mode"""
    if 'timeline_mode' not in st.session_state:
        st.session_state.timeline_mode = 'forensic'  # forensic or live
    if 'current_tenant' not in st.session_state:
        st.session_state.current_tenant = 'default'
    if 'selected_events' not in st.session_state:
        st.session_state.selected_events = []


def render_timeline_controls(tenant_id: str) -> Dict[str, Any]:
    """
    Render timeline playback controls
    
    Returns:
        Dict with control state (play, speed, filters, etc.)
    """
    st.subheader("⏱️ Timeline Replay Controls")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        start_date = st.date_input(
            "Start Date",
            value=datetime.now() - timedelta(days=1),
            key="timeline_start_date"
        )
    
    with col2:
        end_date = st.date_input(
            "End Date",
            value=datetime.now(),
            key="timeline_end_date"
        )
    
    with col3:
        start_hour = st.selectbox("Start Hour", range(24), key="timeline_start_hour")
    
    with col4:
        end_hour = st.selectbox("End Hour", range(24), key="timeline_end_hour")
    
    # Convert to ISO format
    start_time = datetime.combine(start_date, datetime.min.time()).replace(hour=start_hour)
    end_time = datetime.combine(end_date, datetime.min.time()).replace(hour=end_hour)
    
    # Playback controls
    st.markdown("---")
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        if st.button("▶️ Play", key="replay_play"):
            st.session_state.replay_action = "play"
    
    with col2:
        if st.button("⏸️ Pause", key="replay_pause"):
            st.session_state.replay_action = "pause"
    
    with col3:
        if st.button("⏹️ Stop", key="replay_stop"):
            st.session_state.replay_action = "stop"
    
    with col4:
        if st.button("⏪ Step -10", key="replay_step_back"):
            st.session_state.replay_action = "step_back_10"
    
    with col5:
        if st.button("⏩ Step +10", key="replay_step_forward"):
            st.session_state.replay_action = "step_forward_10"
    
    # Speed control
    st.markdown("---")
    col1, col2 = st.columns([2, 1])
    
    with col1:
        speed = st.slider(
            "Playback Speed",
            min_value=0.5,
            max_value=5.0,
            step=0.5,
            value=1.0,
            key="replay_speed",
            format="%.1f×"
        )
    
    with col2:
        st.metric("Current Speed", f"{speed}×")
    
    # Filters
    st.markdown("---")
    st.markdown("**Replay Filters**")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        filter_host = st.text_input("Filter by Host ID", key="filter_host")
    
    with col2:
        filter_user = st.text_input("Filter by User ID", key="filter_user")
    
    with col3:
        filter_event_type = st.selectbox(
            "Filter by Event Type",
            ["", "process_create", "network_connection", "file_access", "registry_write"],
            key="filter_event_type"
        )
    
    filters = {}
    if filter_host:
        filters['host_id'] = filter_host
    if filter_user:
        filters['user_id'] = filter_user
    if filter_event_type:
        filters['event_type'] = filter_event_type
    
    return {
        'start_time': start_time,
        'end_time': end_time,
        'speed': speed,
        'filters': filters,
    }


def render_timeline_progress(engine) -> None:
    """Render timeline progress bar and statistics"""
    stats = engine.get_stats()
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Status", stats.play_state.value.upper())
    
    with col2:
        progress_pct = 0
        if stats.total_events > 0:
            progress_pct = (stats.events_processed / stats.total_events) * 100
        st.metric("Progress", f"{progress_pct:.1f}%")
    
    with col3:
        st.metric("Events Processed", stats.events_processed)
    
    with col4:
        st.metric("Total Events", stats.total_events)
    
    # Progress bar
    if stats.total_events > 0:
        progress = stats.events_processed / stats.total_events
        st.progress(progress, text=f"{stats.events_processed}/{stats.total_events}")


def render_timeline_events(tenant_id: str, events: List[Any]) -> None:
    """
    Render timeline events in a scrollable table
    
    Args:
        tenant_id: Tenant ID
        events: List of TimelineEvent objects
    """
    st.subheader("📋 Timeline Events")
    
    if not events:
        st.info("No events found in selected range")
        return
    
    # Convert events to DataFrame
    event_data = []
    for event in events:
        event_data.append({
            'Timestamp': event.timestamp,
            'Host': event.host_id,
            'User': event.user_id or '-',
            'Process': event.process_name,
            'Event Type': event.event_type,
            'Severity': event.severity,
            'MITRE Techniques': ', '.join(event.mitre_techniques) if event.mitre_techniques else '-',
        })
    
    df = pd.DataFrame(event_data)
    
    # Severity color mapping
    def severity_color(severity):
        colors = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢',
        }
        return colors.get(severity, '⚪')
    
    # Add severity icon
    df['Severity'] = df['Severity'].apply(
        lambda x: f"{severity_color(x)} {x.upper()}"
    )
    
    # Display table
    st.dataframe(
        df,
        use_container_width=True,
        height=400,
    )


def render_timeline_chart(events: List[Any]) -> None:
    """
    Render timeline events as a Plotly timeline chart
    
    Args:
        events: List of TimelineEvent objects
    """
    st.subheader("📊 Event Timeline Visualization")
    
    if not events:
        st.info("No events to visualize")
        return
    
    # Prepare data for timeline
    chart_data = []
    for event in events:
        chart_data.append({
            'timestamp': event.timestamp,
            'event_type': event.event_type,
            'severity': event.severity,
            'process': event.process_name,
            'host': event.host_id,
        })
    
    df = pd.DataFrame(chart_data)
    
    # Create Gantt-like chart
    severity_colors = {
        'critical': '#FF0000',
        'high': '#FF6600',
        'medium': '#FFAA00',
        'low': '#00AA00',
    }
    
    fig = go.Figure()
    
    for idx, row in df.iterrows():
        fig.add_trace(go.Scatter(
            x=[idx],
            y=[row['severity'].upper()],
            mode='markers',
            marker=dict(
                size=12,
                color=severity_colors.get(row['severity'], '#CCCCCC'),
                symbol='circle',
            ),
            text=f"{row['event_type']}<br>{row['process']}<br>{row['host']}",
            hovertemplate='<b>%{text}</b><extra></extra>',
            name=row['severity'],
        ))
    
    fig.update_layout(
        title='Event Timeline',
        xaxis_title='Event Sequence',
        yaxis_title='Severity',
        height=400,
        showlegend=False,
        hovermode='closest',
    )
    
    st.plotly_chart(fig, use_container_width=True)


def render_process_tree(tenant_id: str, process_id: str, events: List[Any]) -> None:
    """
    Render process tree visualization
    
    Args:
        tenant_id: Tenant ID
        process_id: Root process ID
        events: List of TimelineEvent objects
    """
    st.subheader("🌳 Process Tree")
    
    store = get_timeline_store()
    
    # Get events for process tree
    process_events = [e for e in events if e.process_id == process_id]
    
    if not process_events:
        st.info("No events found for this process")
        return
    
    # Build simple process tree display
    for event in process_events:
        indent = "  " * 1  # Could expand based on depth
        col1, col2, col3 = st.columns([1, 2, 4])
        
        with col1:
            st.text(f"{indent}├─ {event.process_id[:8]}")
        
        with col2:
            st.text(event.process_name)
        
        with col3:
            st.text(f"{event.event_type} [{event.severity.upper()}]")


def render_attack_chain_visualization(chain) -> None:
    """
    Render attack chain visualization
    
    Args:
        chain: AttackChain object
    """
    st.subheader("⚔️ Attack Chain Analysis")
    
    # Chain header
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Chain ID", chain.chain_id[:16] + "...")
    
    with col2:
        st.metric("Total Events", len(chain.events))
    
    with col3:
        st.metric("Severity", chain.severity.upper())
    
    with col4:
        st.metric("Anomaly Score", f"{chain.total_anomaly_score:.1f}")
    
    # Kill chain progression
    st.markdown("---")
    st.markdown("**Kill Chain Progression**")
    
    if chain.kill_chain_progression:
        for phase, ts in chain.kill_chain_progression:
            st.write(f"🔗 {phase.replace('_', ' ').title()}")
    else:
        st.info("No MITRE ATT&CK phases detected")
    
    # Tags
    st.markdown("---")
    if chain.tags:
        st.markdown("**Tags**")
        col1, col2, col3 = st.columns([1, 1, 1])
        for i, tag in enumerate(chain.tags):
            if i % 3 == 0:
                col1.write(f"🏷️ {tag}")
            elif i % 3 == 1:
                col2.write(f"🏷️ {tag}")
            else:
                col3.write(f"🏷️ {tag}")
    
    # Attack chain events
    st.markdown("---")
    st.markdown("**Event Sequence**")
    
    for i, node in enumerate(chain.events, 1):
        with st.expander(f"{i}. {node.event_type} - {node.process_name}"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**Timestamp**: {node.timestamp}")
                st.write(f"**Process ID**: {node.process_id}")
                st.write(f"**Process Name**: {node.process_name}")
                st.write(f"**Severity**: {node.severity.upper()}")
            
            with col2:
                st.write(f"**Event Type**: {node.event_type}")
                st.write(f"**Anomaly Score**: {node.anomaly_score:.1f}")
                if node.kill_chain_phase:
                    st.write(f"**Kill Chain Phase**: {node.kill_chain_phase.value}")
                if node.mitre_techniques:
                    st.write(f"**MITRE Techniques**: {', '.join(node.mitre_techniques)}")


def render_timeline_mode(tenant_id: str = "default") -> None:
    """
    Main timeline mode UI
    
    Args:
        tenant_id: Tenant ID for filtering
    """
    initialize_timeline_session_state()
    
    st.markdown("# ⏱️ Attack Timeline Replay (Splunk-style Forensics)")
    
    st.markdown("""
    Replay security events like a video timeline. Filter by host, user, process,
    or MITRE technique. Correlate events into attack chains and analyze kill chain progression.
    """)
    
    st.markdown("---")
    
    # Sidebar for mode selection
    mode = st.radio(
        "Timeline Mode",
        ["Forensic (Replay)", "Live Stream", "Attack Chains"],
        horizontal=True,
        key="timeline_mode_selector"
    )
    
    st.markdown("---")
    
    if mode == "Forensic (Replay)":
        render_forensic_mode(tenant_id)
    
    elif mode == "Live Stream":
        render_live_stream_mode(tenant_id)
    
    elif mode == "Attack Chains":
        render_attack_chains_mode(tenant_id)


def render_forensic_mode(tenant_id: str) -> None:
    """Render forensic (replay) mode"""
    
    store = get_timeline_store()
    engine = get_replay_engine(store)
    
    # Timeline controls
    controls = render_timeline_controls(tenant_id)
    
    # Load timeline
    if st.button("Load Timeline", key="load_timeline"):
        with st.spinner("Loading events..."):
            count = engine.load_range(
                tenant_id,
                controls['start_time'],
                controls['end_time'],
                controls['filters']
            )
            st.success(f"Loaded {count} events")
    
    st.markdown("---")
    
    # Playback controls
    col1, col2 = st.columns([2, 1])
    
    with col1:
        if st.button("▶️ Start Playback", key="start_playback"):
            engine.play(speed=controls['speed'])
            st.toast("Playback started ✅")
    
    with col2:
        if st.button("⏸️ Pause", key="pause_playback"):
            engine.pause()
            st.toast("Paused ⏸️")
    
    # Progress display
    render_timeline_progress(engine)
    
    st.markdown("---")
    
    # Events display
    if engine.events:
        # Show as timeline
        render_timeline_chart(engine.events)
        
        # Show as table
        render_timeline_events(tenant_id, engine.events)


def render_live_stream_mode(tenant_id: str) -> None:
    """Render live stream mode"""
    st.info("Live stream mode would connect to Kafka for real-time event display")
    
    # Placeholder for live streaming
    col1, col2 = st.columns(2)
    
    with col1:
        st.metric("Live Events/sec", 42)
    
    with col2:
        st.metric("Buffer Utilization", "35%")


def render_attack_chains_mode(tenant_id: str) -> None:
    """Render attack chain analysis mode"""
    
    store = get_timeline_store()
    correlator = get_correlator(store)
    
    st.subheader("🔍 Attack Chain Correlator")
    
    # Get attack chains
    chains = correlator.get_chains(tenant_id)
    
    if not chains:
        st.info("No attack chains found. Load timeline and click 'Correlate' first.")
        return
    
    # Chain selector
    chain_options = {c.chain_id[:20]: c for c in chains}
    selected_chain_id = st.selectbox(
        "Select Attack Chain",
        list(chain_options.keys()),
        format_func=lambda x: f"{x} ({chain_options[x].severity.upper()})"
    )
    
    if selected_chain_id:
        selected_chain = chain_options[selected_chain_id]
        render_attack_chain_visualization(selected_chain)


# ============================================================================
# Public API
# ============================================================================

def render_timeline_section(tenant_id: str = "default"):
    """
    Render complete timeline section in Streamlit app
    
    Usage:
        from dashboard.timeline_ui import render_timeline_section
        
        if st.session_state.current_tab == "Timeline":
            render_timeline_section("my_tenant")
    """
    render_timeline_mode(tenant_id)
