"""
Timeline Visualization Helpers

Advanced visualization utilities for:
- Process tree diagrams
- Attack chain flow graphs
- Timeline heat maps
- Threat progression charts
"""

import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import networkx as nx
from typing import Dict, List, Any, Optional
from collections import defaultdict


def create_process_tree_diagram(process_tree: Dict[str, Any], root_process_id: str) -> go.Figure:
    """
    Create process tree visualization
    
    Args:
        process_tree: Process tree dictionary with parent/child relationships
        root_process_id: Root process ID
    
    Returns:
        Plotly Figure
    """
    # Build directed graph
    G = nx.DiGraph()
    
    # Add edges for parent-child relationships
    for parent_id, node_data in process_tree.items():
        if node_data.get('process_name'):
            G.add_node(parent_id, label=node_data['process_name'][:20])
            
            for child_id in node_data.get('children', []):
                G.add_edge(parent_id, child_id)
    
    # Use hierarchical layout
    pos = nx.spring_layout(G, k=2, iterations=50, seed=42)
    
    # Create edges
    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.append(x0)
        edge_x.append(x1)
        edge_x.append(None)
        edge_y.append(y0)
        edge_y.append(y1)
        edge_y.append(None)
    
    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        mode='lines',
        line=dict(width=0.5, color='#888'),
        hoverinfo='none',
        showlegend=False,
    )
    
    # Create nodes
    node_x = []
    node_y = []
    node_text = []
    node_size = []
    
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        
        label = G.nodes[node].get('label', node[:16])
        node_text.append(label)
        
        # Size by depth
        size = 20 if node == root_process_id else 15
        node_size.append(size)
    
    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        text=node_text,
        textposition='top center',
        hoverinfo='text',
        marker=dict(
            showscale=False,
            color='#1f77b4',
            size=node_size,
            line_width=2
        ),
    )
    
    # Create figure
    fig = go.Figure(data=[edge_trace, node_trace])
    
    fig.update_layout(
        title='Process Tree Hierarchy',
        showlegend=False,
        hovermode='closest',
        margin=dict(b=0, l=0, r=0, t=40),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        height=600,
    )
    
    return fig


def create_attack_chain_flow(chain) -> go.Figure:
    """
    Create attack chain flow visualization (Sankey diagram)
    
    Args:
        chain: AttackChain object
    
    Returns:
        Plotly Figure
    """
    if not chain.events:
        return go.Figure()
    
    # Build Sankey diagram
    source = []
    target = []
    value = []
    colors = []
    
    # Map kill chain phases to indices
    phase_to_idx = {}
    labels = []
    idx = 0
    
    for event in chain.events:
        if event.kill_chain_phase:
            phase = event.kill_chain_phase.value
            if phase not in phase_to_idx:
                phase_to_idx[phase] = idx
                labels.append(phase.replace('_', ' ').title())
                idx += 1
    
    # Create flow between phases
    prev_phase_idx = None
    for event in chain.events:
        if event.kill_chain_phase:
            current_phase_idx = phase_to_idx.get(event.kill_chain_phase.value)
            
            if prev_phase_idx is not None and current_phase_idx != prev_phase_idx:
                source.append(prev_phase_idx)
                target.append(current_phase_idx)
                value.append(1)
                
                # Color based on severity
                severity_color = {
                    'critical': 'rgba(255, 0, 0, 0.4)',
                    'high': 'rgba(255, 102, 0, 0.4)',
                    'medium': 'rgba(255, 170, 0, 0.4)',
                    'low': 'rgba(0, 170, 0, 0.4)',
                }
                colors.append(severity_color.get(event.severity, 'rgba(100, 100, 100, 0.4)'))
            
            prev_phase_idx = current_phase_idx
    
    fig = go.Figure(data=[go.Sankey(
        node=dict(
            pad=15,
            thickness=20,
            line=dict(color='black', width=0.5),
            label=labels,
        ),
        link=dict(
            source=source,
            target=target,
            value=value,
            color=colors,
        )
    )])
    
    fig.update_layout(title='Attack Chain Flow (Kill Chain Progression)', height=400)
    
    return fig


def create_event_timeline_heatmap(events: List[Any]) -> go.Figure:
    """
    Create heatmap of event severity over time
    
    Args:
        events: List of TimelineEvent objects
    
    Returns:
        Plotly Figure
    """
    if not events:
        return go.Figure()
    
    # Convert to DataFrame
    df = pd.DataFrame([
        {
            'timestamp': e.timestamp,
            'severity': e.severity,
            'event_type': e.event_type,
            'process': e.process_name,
        }
        for e in events
    ])
    
    # Map severity to numeric
    severity_map = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
    df['severity_score'] = df['severity'].map(severity_map)
    
    # Group by event type and count
    event_severity = df.groupby(['event_type', 'severity']).size().unstack(fill_value=0)
    
    fig = px.imshow(
        event_severity,
        labels=dict(x='Severity', y='Event Type', color='Count'),
        color_continuous_scale='YlOrRd',
        title='Event Type by Severity Heatmap',
    )
    
    fig.update_layout(height=400)
    
    return fig


def create_threat_progression_chart(chain) -> go.Figure:
    """
    Create threat score progression over attack timeline
    
    Args:
        chain: AttackChain object
    
    Returns:
        Plotly Figure
    """
    if not chain.events:
        return go.Figure()
    
    # Calculate cumulative anomaly score
    cumulative_scores = []
    timestamps = []
    event_names = []
    
    cumulative = 0.0
    for event in chain.events:
        cumulative += event.anomaly_score
        cumulative_scores.append(min(100.0, cumulative))
        timestamps.append(event.timestamp)
        event_names.append(f"{event.event_type}\n{event.process_name[:20]}")
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        x=timestamps,
        y=cumulative_scores,
        mode='lines+markers',
        name='Threat Score',
        fill='tozeroy',
        marker=dict(size=8, color='#FF6666'),
        line=dict(color='#FF6666', width=3),
        hovertext=event_names,
        hoverinfo='text+y',
    ))
    
    # Add severity zones
    fig.add_hrect(y0=0, y1=25, annotation_text="Low", annotation_position="right",
                  fillcolor="#00AA00", opacity=0.1, layer="below", line_width=0)
    fig.add_hrect(y0=25, y1=50, annotation_text="Medium", annotation_position="right",
                  fillcolor="#FFAA00", opacity=0.1, layer="below", line_width=0)
    fig.add_hrect(y0=50, y1=75, annotation_text="High", annotation_position="right",
                  fillcolor="#FF6600", opacity=0.1, layer="below", line_width=0)
    fig.add_hrect(y0=75, y1=100, annotation_text="Critical", annotation_position="right",
                  fillcolor="#FF0000", opacity=0.1, layer="below", line_width=0)
    
    fig.update_layout(
        title='Threat Score Progression',
        xaxis_title='Timeline',
        yaxis_title='Cumulative Threat Score',
        height=400,
        showlegend=False,
    )
    
    return fig


def create_mitre_technique_chart(chain) -> go.Figure:
    """
    Create MITRE technique coverage visualization
    
    Args:
        chain: AttackChain object
    
    Returns:
        Plotly Figure
    """
    # Count techniques
    technique_counts = defaultdict(int)
    tactic_counts = defaultdict(int)
    
    for event in chain.events:
        for tech in event.mitre_techniques:
            technique_counts[tech] += 1
        for tactic in event.mitre_tactics:
            tactic_counts[tactic] += 1
    
    # Create bar chart
    if technique_counts:
        techniques = list(technique_counts.keys())
        counts = list(technique_counts.values())
        
        fig = px.bar(
            x=counts,
            y=techniques,
            orientation='h',
            title='MITRE Techniques Used',
            labels={'x': 'Count', 'y': 'Technique'},
        )
        
        fig.update_layout(height=400)
        
        return fig
    
    return go.Figure()


def create_event_distribution_chart(events: List[Any]) -> go.Figure:
    """
    Create distribution of events over time
    
    Args:
        events: List of TimelineEvent objects
    
    Returns:
        Plotly Figure
    """
    if not events:
        return go.Figure()
    
    df = pd.DataFrame([
        {
            'timestamp': e.timestamp,
            'event_type': e.event_type,
        }
        for e in events
    ])
    
    # Count by event type
    event_counts = df['event_type'].value_counts()
    
    fig = px.pie(
        values=event_counts.values,
        names=event_counts.index,
        title='Event Distribution by Type',
    )
    
    fig.update_layout(height=400)
    
    return fig


# ============================================================================
# Helper functions for dashboard integration
# ============================================================================

def format_timeline_event_for_display(event) -> Dict[str, str]:
    """Format event for timeline display"""
    return {
        'Time': event.timestamp,
        'Host': event.host_id,
        'User': event.user_id or '-',
        'Process': event.process_name,
        'Event': event.event_type.replace('_', ' ').title(),
        'Severity': event.severity.upper(),
        'Techniques': ', '.join(event.mitre_techniques) if event.mitre_techniques else '-',
    }


def get_event_severity_color(severity: str) -> str:
    """Get color for severity level"""
    colors = {
        'critical': '#FF0000',
        'high': '#FF6600',
        'medium': '#FFAA00',
        'low': '#00AA00',
    }
    return colors.get(severity, '#CCCCCC')


def get_event_severity_emoji(severity: str) -> str:
    """Get emoji for severity level"""
    emojis = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🟢',
    }
    return emojis.get(severity, '⚪')
