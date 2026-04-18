"""
Timeline Replay System - Complete Demo

Demonstrates:
1. Loading security events into timeline
2. Replaying timeline with play/pause/step controls
3. Correlating events into attack chains
4. Analyzing kill chain progression
5. Filtering and forensic queries
"""

import sys
from datetime import datetime, timedelta
import time

# Add project root to path
sys.path.insert(0, '.')

from edr_behavior.timeline_store import init_timeline_store, TimelineEvent, EventMode
from edr_behavior.replay_engine import init_replay_engine
from edr_behavior.attack_chain_correlator import init_correlator


def generate_test_events() -> list:
    """Generate realistic attack timeline for demo"""
    base_time = datetime.now() - timedelta(hours=1)
    
    events = []
    
    # Event 1: Initial access (reconnaissance)
    events.append(TimelineEvent(
        timestamp=(base_time.replace(microsecond=0).isoformat() + 'Z'),
        event_id='evt_001',
        tenant_id='demo_tenant',
        host_id='host_001',
        user_id='user_admin',
        process_id='proc_001',
        parent_process_id='proc_sys',
        process_name='explorer.exe',
        event_type='process_create',
        severity='medium',
        source='edr_agent',
        mitre_techniques=['T1595', 'T1592'],
        mitre_tactics=['reconnaissance'],
        details={'command_line': 'explorer.exe'},
        mode=EventMode.FORENSIC,
    ))
    
    # Event 2: Suspicious process (delivery)
    base_time = base_time + timedelta(minutes=5)
    events.append(TimelineEvent(
        timestamp=(base_time.replace(microsecond=0).isoformat() + 'Z'),
        event_id='evt_002',
        tenant_id='demo_tenant',
        host_id='host_001',
        user_id='user_admin',
        process_id='proc_002',
        parent_process_id='proc_001',
        process_name='powershell.exe',
        event_type='process_create',
        severity='high',
        source='edr_agent',
        mitre_techniques=['T1086'],
        mitre_tactics=['execution'],
        details={'command_line': 'powershell.exe -NoProfile -ExecutionPolicy Bypass'},
        mode=EventMode.FORENSIC,
    ))
    
    # Event 3: Credential access attempt
    base_time = base_time + timedelta(minutes=3)
    events.append(TimelineEvent(
        timestamp=(base_time.replace(microsecond=0).isoformat() + 'Z'),
        event_id='evt_003',
        tenant_id='demo_tenant',
        host_id='host_001',
        user_id='user_admin',
        process_id='proc_003',
        parent_process_id='proc_002',
        process_name='lsass.exe',
        event_type='process_create',
        severity='critical',
        source='edr_agent',
        mitre_techniques=['T1110', 'T1555'],
        mitre_tactics=['credential-access'],
        details={'accessed_resource': 'SAM'},
        mode=EventMode.FORENSIC,
    ))
    
    # Event 4: Privilege escalation
    base_time = base_time + timedelta(minutes=2)
    events.append(TimelineEvent(
        timestamp=(base_time.replace(microsecond=0).isoformat() + 'Z'),
        event_id='evt_004',
        tenant_id='demo_tenant',
        host_id='host_001',
        user_id='system',
        process_id='proc_004',
        parent_process_id='proc_003',
        process_name='token.exe',
        event_type='process_create',
        severity='critical',
        source='edr_agent',
        mitre_techniques=['T1068', 'T1134'],
        mitre_tactics=['privilege-escalation'],
        details={'privilege_level': 'SYSTEM'},
        mode=EventMode.FORENSIC,
    ))
    
    # Event 5: Persistence mechanism
    base_time = base_time + timedelta(minutes=4)
    events.append(TimelineEvent(
        timestamp=(base_time.replace(microsecond=0).isoformat() + 'Z'),
        event_id='evt_005',
        tenant_id='demo_tenant',
        host_id='host_001',
        user_id='system',
        process_id='proc_004',
        parent_process_id='proc_003',
        process_name='schtasks.exe',
        event_type='process_create',
        severity='high',
        source='edr_agent',
        mitre_techniques=['T1053', 'T1547'],
        mitre_tactics=['persistence', 'privilege-escalation'],
        details={'task_name': 'WindowsUpdate'},
        mode=EventMode.FORENSIC,
    ))
    
    # Event 6: Network communication (C2)
    base_time = base_time + timedelta(minutes=3)
    events.append(TimelineEvent(
        timestamp=(base_time.replace(microsecond=0).isoformat() + 'Z'),
        event_id='evt_006',
        tenant_id='demo_tenant',
        host_id='host_001',
        user_id='system',
        process_id='proc_005',
        parent_process_id='proc_004',
        process_name='powershell.exe',
        event_type='network_connection',
        severity='critical',
        source='edr_agent',
        mitre_techniques=['T1071', 'T1095'],
        mitre_tactics=['command-and-control'],
        details={'destination': '192.168.1.100:4444', 'protocol': 'TCP'},
        mode=EventMode.FORENSIC,
    ))
    
    # Event 7: Data exfiltration
    base_time = base_time + timedelta(minutes=5)
    events.append(TimelineEvent(
        timestamp=(base_time.replace(microsecond=0).isoformat() + 'Z'),
        event_id='evt_007',
        tenant_id='demo_tenant',
        host_id='host_001',
        user_id='system',
        process_id='proc_005',
        parent_process_id='proc_004',
        process_name='cmd.exe',
        event_type='file_access',
        severity='critical',
        source='edr_agent',
        mitre_techniques=['T1041', 'T1020'],
        mitre_tactics=['exfiltration'],
        details={'file_path': 'C:\\Users\\Admin\\Documents\\SecretFile.xlsx'},
        mode=EventMode.FORENSIC,
    ))
    
    return events


def demo_timeline_storage():
    """Demo 1: Timeline event storage and querying"""
    print("\n" + "="*70)
    print("DEMO 1: TIMELINE EVENT STORAGE AND QUERYING")
    print("="*70)
    
    # Initialize store
    store = init_timeline_store(max_events=1000)
    
    # Generate and add events
    print("\n📥 Adding events to timeline store...")
    events = generate_test_events()
    
    for event in events:
        event_id = store.add_event(event)
        print(f"   ✅ Added {event.event_type:25} [{event.severity:8}] {event_id[:20]}...")
    
    # Get statistics
    print("\n📊 Timeline Statistics:")
    stats = store.get_stats('demo_tenant')
    print(f"   Total Events: {stats['total_events']}")
    print(f"   Last Event: {stats['last_event_timestamp']}")
    
    # Query by time range
    print("\n🔍 Querying events in time range...")
    start = datetime.now() - timedelta(hours=2)
    end = datetime.now()
    
    results = store.query_range('demo_tenant', start, end)
    print(f"   Found {len(results)} events")
    
    # Query with filters
    print("\n🔎 Querying with filters (severity='critical')...")
    results = store.query_range(
        'demo_tenant', start, end,
        filters={'severity': 'critical'}
    )
    print(f"   Found {len(results)} critical events:")
    for event in results:
        print(f"     - {event.process_name:20} {event.event_type}")
    
    return store


def demo_timeline_replay(store):
    """Demo 2: Timeline replay with play/pause/step controls"""
    print("\n" + "="*70)
    print("DEMO 2: TIMELINE REPLAY WITH CONTROLS")
    print("="*70)
    
    # Initialize replay engine
    engine = init_replay_engine(store)
    
    # Load timeline
    print("\n⏳ Loading timeline for replay...")
    start = datetime.now() - timedelta(hours=2)
    end = datetime.now()
    
    count = engine.load_range('demo_tenant', start, end)
    print(f"   Loaded {count} events for replay")
    
    # Display initial stats
    stats = engine.get_stats()
    print(f"   Status: {stats.play_state.value}")
    print(f"   Total Events: {stats.total_events}")
    print(f"   Current Index: {stats.events_processed}")
    
    # Demo step forward
    print("\n⏩ Stepping forward 2 events...")
    for i in range(2):
        event = engine.step_forward(1)
        if event:
            print(f"   Event {i+1}: {event.process_name:20} {event.event_type:20} [{event.severity}]")
    
    # Demo step backward
    print("\n⏪ Stepping backward 1 event...")
    event = engine.step_backward(1)
    if event:
        print(f"   Back to: {event.process_name:20} {event.event_type:20}")
    
    # Demo jump to
    print("\n⏱️  Jumping to middle of timeline...")
    if engine.events:
        mid_time = datetime.fromisoformat(engine.events[len(engine.events)//2].timestamp.replace('Z', '+00:00'))
        event = engine.jump_to(mid_time)
        if event:
            print(f"   Jumped to: {event.process_name:20} {event.event_type:20}")
    
    # Demo filter
    print("\n🔽 Applying filter (severity='critical')...")
    engine.set_filter('severity', 'critical')
    stats = engine.get_stats()
    print(f"   Filtered to {stats.total_events} critical events")
    
    return engine


def demo_attack_chain_correlation(store):
    """Demo 3: Event correlation into attack chains"""
    print("\n" + "="*70)
    print("DEMO 3: ATTACK CHAIN CORRELATION")
    print("="*70)
    
    # Initialize correlator
    correlator = init_correlator(store)
    
    # Get events for correlation - use wider time range to ensure we capture all
    print("\n🔗 Correlating events into attack chain...")
    start = datetime.now() - timedelta(hours=2)
    end = datetime.now() + timedelta(hours=1)  # Wider range to capture all
    
    events = store.query_range('demo_tenant', start, end)
    
    if not events:
        print("   ⚠️  No events found in timeline store")
        print(f"   Store stats: {store.get_stats('demo_tenant')}")
        return None
    
    # Correlate events
    chain = correlator.correlate_events('demo_tenant', events)
    
    print(f"   Chain ID: {chain.chain_id}")
    print(f"   Root Process ID: {chain.root_process_id}")
    print(f"   Total Events: {len(chain.events)}")
    print(f"   Severity: {chain.severity.upper()}")
    print(f"   Anomaly Score: {chain.total_anomaly_score:.1f}")
    
    # Display attack chain progression
    print(f"\n⚔️  Kill Chain Progression:")
    for phase, ts in chain.kill_chain_progression:
        print(f"   → {phase.replace('_', ' ').title()}")
    
    # Display chain events
    print(f"\n📋 Attack Chain Events:")
    for i, node in enumerate(chain.events, 1):
        print(f"   {i}. {node.event_type:20} [{node.severity:8}] {node.process_name:20} (anomaly: {node.anomaly_score:.1f})")
    
    # Display tags
    print(f"\n🏷️  Auto-Generated Tags:")
    for tag in chain.tags:
        print(f"   • {tag}")
    
    return chain


def demo_forensic_mode(store):
    """Demo 4: Forensic mode investigation"""
    print("\n" + "="*70)
    print("DEMO 4: FORENSIC MODE INVESTIGATION")
    print("="*70)
    
    # Use existing store instead of reinitializing
    start = datetime.now() - timedelta(hours=2)
    end = datetime.now() + timedelta(hours=1)
    
    # Query process tree
    print("\n🌳 Querying process tree for forensics...")
    
    process_tree = store.query_process_tree(
        'demo_tenant', 'proc_002', start, end,
        include_children=True, include_parent=True
    )
    
    if process_tree:
        print(f"   Root Process: {process_tree['root_process_id']}")
        if process_tree['parent']:
            print(f"   Parent: {process_tree['parent'].process_name}")
        children = process_tree.get('children', {})
        print(f"   Children: {len(children)} processes")
        for child_id, child_event in list(children.items())[:5]:
            print(f"     - {child_event.process_name}")
    
    # Timeline query with multiple filters
    print("\n🔍 Complex forensic query (host + severity filter)...")
    results = store.query_range(
        'demo_tenant', start, end,
        filters={'host_id': 'host_001', 'severity': 'critical'}
    )
    print(f"   Found {len(results)} critical events on host_001")
    for evt in results:
        print(f"     - {evt.process_name:20} [{evt.severity:8}]")
    
    print("\n✅ Forensic demo complete")


def main():
    """Run all demos"""
    print("\n" + "="*70)
    print("🎬 REAL-TIME ATTACK TIMELINE REPLAY SYSTEM - COMPLETE DEMO")
    print("="*70)
    print("\nDemonstrating Splunk-style forensics mode with:")
    print("  1️⃣  Timeline event storage and querying")
    print("  2️⃣  Replay engine with play/pause/step controls")
    print("  3️⃣  Attack chain correlation and kill chain analysis")
    print("  4️⃣  Forensic mode investigation")
    
    try:
        # Run demos
        store = demo_timeline_storage()
        engine = demo_timeline_replay(store)
        chain = demo_attack_chain_correlation(store)
        demo_forensic_mode(store)
        
        # Final summary
        print("\n" + "="*70)
        print("✅ DEMO COMPLETE")
        print("="*70)
        print("\n📊 Summary:")
        stats = store.get_stats('demo_tenant')
        print(f"   Events stored: {stats.get('total_events', 0)}")
        if chain:
            print(f"   Attack chains: 1 (with {len(chain.events)} events)")
            print(f"   Kill chain phases: {len(chain.kill_chain_progression)}")
            print(f"   Threat score: {chain.total_anomaly_score:.1f}/100")
            print(f"   Detection tags: {len(chain.tags)}")
        else:
            print(f"   Attack chains: 0 (no chain generated)")
        
        print("\n🚀 Features demonstrated:")
        print("   ✓ Append-only event log with multi-dimensional indexing")
        print("   ✓ Timeline replay with video-like controls")
        print("   ✓ Process tree reconstruction for forensics")
        print("   ✓ Event correlation into attack chains")
        print("   ✓ MITRE ATT&CK technique mapping")
        print("   ✓ Kill chain progression detection")
        print("   ✓ Anomaly score calculation")
        print("   ✓ Multi-tenant isolation")
        
        print("\n📖 Next steps:")
        print("   1. Use timeline_store.TimelineEventStore for event ingestion")
        print("   2. Use replay_engine.TimelineReplayEngine for timeline playback")
        print("   3. Use attack_chain_correlator.AttackChainCorrelator for correlation")
        print("   4. Integrate with FastAPI backend (backend/timeline_api.py)")
        print("   5. Use Streamlit UI (dashboard/timeline_ui.py) for visualization")
        
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
