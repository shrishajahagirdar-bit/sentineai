"""
UEBA Baseline Rebuild Script

This script rebuilds user behavioral baselines from collected authentication events.

Usage:
    python scripts/rebuild_ueba_baselines.py [--auth-events] [--from-file PATH]

Options:
    --auth-events: Rebuild only from filtered auth events (recommended)
    --from-file: Rebuild from specific auth events file
"""

import sys
import json
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from risk_engine.ueba import UebaEngine
from collector.storage import read_jsonl, append_jsonl
from sentinel_config import CONFIG
from core.safe_wrapper import log_health_event


def rebuild_ueba_baselines(auth_events_file=None):
    """Rebuild UEBA baselines from authentication events."""
    
    print("\n" + "="*70)
    print("🔄 UEBA Baseline Rebuild")
    print("="*70)
    
    # Determine source
    if auth_events_file:
        source_file = Path(auth_events_file)
        print(f"\n📁 Loading from: {source_file}")
    else:
        source_file = CONFIG.auth_event_store
        print(f"\n📁 Loading from: {CONFIG.auth_event_store}")
    
    if not source_file.exists():
        print(f"❌ File not found: {source_file}")
        return False
    
    # Load events
    print("\n⏳ Loading authentication events...")
    events = read_jsonl(source_file, limit=None)
    if not events:
        print("⚠️  No events found")
        return False
    
    print(f"✓ Loaded {len(events)} events")
    
    # Analyze event types
    event_types = {}
    for event in events:
        etype = event.get("event_type", "unknown")
        event_types[etype] = event_types.get(etype, 0) + 1
    
    print("\n📊 Event Distribution:")
    for etype, count in sorted(event_types.items(), key=lambda x: -x[1]):
        print(f"  • {etype}: {count}")
    
    # Get unique users
    users = set()
    for event in events:
        user = event.get("user")
        if user and user != "unknown":
            users.add(user)
    
    print(f"\n👥 Unique users: {len(users)}")
    if len(users) <= 10:
        for user in sorted(users):
            user_events = [e for e in events if e.get("user") == user]
            print(f"  • {user}: {len(user_events)} events")
    else:
        for user in sorted(users)[:10]:
            user_events = [e for e in events if e.get("user") == user]
            print(f"  • {user}: {len(user_events)} events")
        print(f"  ... and {len(users) - 10} more users")
    
    # Rebuild baselines
    print("\n🏗️  Building baselines...")
    engine = UebaEngine()
    baselines = engine.rebuild(events)
    
    print(f"✓ Built {len(baselines)} user profiles")
    
    # Display baseline summaries
    print("\n📈 Baseline Summaries:")
    for user in sorted(baselines.keys())[:5]:
        profile = baselines[user]
        print(f"\n  📌 {user}")
        print(f"     • Total logins: {profile.get('total_logins', 0)}")
        print(f"     • Success rate: {(1 - profile.get('failed_login_rate', 0)) * 100:.1f}%")
        print(f"     • Known devices: {profile.get('device_count', 0)}")
        print(f"     • Known IPs: {profile.get('ip_count', 0)}")
        print(f"     • Avg login hour: {profile.get('avg_login_hour', 'N/A')}")
    
    if len(baselines) > 5:
        print(f"\n  ... and {len(baselines) - 5} more users")
    
    # Verify saved baselines
    print("\n✅ Baselines saved to: " + str(CONFIG.baseline_store))
    
    print("\n" + "="*70)
    print(f"✓ UEBA baseline rebuild complete")
    print("="*70 + "\n")
    
    return True


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Rebuild UEBA baselines")
    parser.add_argument(
        "--from-file",
        type=str,
        help="Rebuild from specific auth events file",
    )
    parser.add_argument(
        "--auth-events",
        action="store_true",
        help="Use filtered auth events (default)",
    )
    
    args = parser.parse_args()
    
    try:
        success = rebuild_ueba_baselines(auth_events_file=args.from_file)
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
