"""
UEBA System Validation Script

Validates the UEBA implementation end-to-end.
"""

import sys
import json
from pathlib import Path
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent))

from collector.auth.windows_auth_collector import WindowsAuthCollector
from ml_engine.ueba_transformer import UebaEventTransformer
from ml_engine.ueba_filter import UebaEventFilter
from risk_engine.ueba import UebaEngine
from collector.storage import read_jsonl, load_json
from sentinel_config import CONFIG


def test_auth_collector():
    """Test Windows auth collector."""
    print("\n" + "="*70)
    print("🧪 Testing Windows Auth Collector")
    print("="*70)
    
    try:
        collector = WindowsAuthCollector()
        print(f"✓ Collector initialized")
        print(f"  Hostname: {collector.hostname}")
        
        events = collector.collect()
        print(f"✓ Collected {len(events)} auth events")
        
        if events:
            sample = events[0]
            print(f"\n  Sample event:")
            print(f"    • Event ID: {sample.get('event_id')}")
            print(f"    • User: {sample.get('user')}")
            print(f"    • Host: {sample.get('host')}")
            print(f"    • IP: {sample.get('ip_address')}")
            print(f"    • Logon Type: {sample.get('logon_type')}")
        
        return True
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False


def test_ueba_transformer():
    """Test UEBA transformer."""
    print("\n" + "="*70)
    print("🧪 Testing UEBA Transformer")
    print("="*70)
    
    try:
        # Create mock auth event
        mock_event = {
            "event_type": "auth_event",
            "event_id": 4624,
            "user": "testuser",
            "host": "TESTPC",
            "timestamp": datetime.utcnow().isoformat(),
            "ip_address": "192.168.1.100",
            "logon_type": "Interactive",
            "raw_source": "windows_security",
        }
        
        print(f"✓ Created mock event")
        
        # Transform
        transformer = UebaEventTransformer()
        result = transformer.to_ueba_event(mock_event)
        
        if result:
            print(f"✓ Transformed to UEBA format")
            print(f"  • Event type: {result.get('event_type')}")
            print(f"  • User: {result.get('user')}")
            print(f"  • Device: {result.get('device')}")
            print(f"  • Source: {result.get('source')}")
            print(f"  • Risk signals: {result.get('risk_signals')}")
            return True
        else:
            print(f"❌ Transform returned None")
            return False
            
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def test_ueba_filter():
    """Test UEBA filter."""
    print("\n" + "="*70)
    print("🧪 Testing UEBA Filter")
    print("="*70)
    
    try:
        # Valid event
        valid_event = {
            "event_type": "login_success",
            "user": "testuser",
            "source": "windows_auth",
            "device": "TESTPC",
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        # Invalid event (wrong source)
        invalid_event_1 = {
            "event_type": "login_success",
            "user": "testuser",
            "source": "sysmon",  # Wrong source
            "device": "TESTPC",
        }
        
        # Invalid event (wrong type)
        invalid_event_2 = {
            "event_type": "process_creation",  # Wrong type
            "user": "testuser",
            "source": "windows_auth",
            "device": "TESTPC",
        }
        
        # Invalid event (unknown user)
        invalid_event_3 = {
            "event_type": "login_success",
            "user": "unknown",  # Invalid user
            "source": "windows_auth",
            "device": "TESTPC",
        }
        
        filter_obj = UebaEventFilter()
        
        result1 = filter_obj.filter(valid_event)
        print(f"✓ Valid event: {'✓ PASSED' if result1 else '❌ REJECTED'}")
        
        result2 = filter_obj.filter(invalid_event_1)
        print(f"✓ Wrong source: {'✓ REJECTED' if not result2 else '❌ PASSED'}")
        
        result3 = filter_obj.filter(invalid_event_2)
        print(f"✓ Wrong type: {'✓ REJECTED' if not result3 else '❌ PASSED'}")
        
        result4 = filter_obj.filter(invalid_event_3)
        print(f"✓ Unknown user: {'✓ REJECTED' if not result4 else '❌ PASSED'}")
        
        return result1 and not result2 and not result3 and not result4
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False


def test_ueba_baseline():
    """Test UEBA baseline engine."""
    print("\n" + "="*70)
    print("🧪 Testing UEBA Baseline Engine")
    print("="*70)
    
    try:
        # Create mock UEBA events
        mock_events = []
        for hour in range(9, 17):  # 9 AM to 5 PM
            for i in range(3):
                mock_events.append({
                    "user": "testuser",
                    "device": "LAPTOP01",
                    "event_type": "login_success",
                    "timestamp": (datetime.now() - timedelta(days=i)).replace(hour=hour).isoformat(),
                    "source": "windows_auth",
                    "ip_address": "192.168.1.100",
                    "logon_type": "Interactive",
                })
        
        print(f"✓ Created {len(mock_events)} mock UEBA events")
        
        # Build baselines
        engine = UebaEngine()
        baselines = engine.rebuild(mock_events)
        
        print(f"✓ Built baselines for {len(baselines)} users")
        
        if "testuser" in baselines:
            profile = baselines["testuser"]
            print(f"\n  📌 testuser profile:")
            print(f"     • Total logins: {profile.get('total_logins')}")
            print(f"     • Success count: {profile.get('login_success_count')}")
            print(f"     • Known devices: {profile.get('known_devices')}")
            print(f"     • Known IPs: {profile.get('known_ips')}")
            print(f"     • Login hours: {profile.get('login_time_distribution')}")
            
            # Test scoring
            test_event = {
                "user": "testuser",
                "device": "LAPTOP01",
                "event_type": "login_success",
                "timestamp": datetime.now().replace(hour=12).isoformat(),
                "ip_address": "192.168.1.100",
                "logon_type": "Interactive",
            }
            
            score, reasons = engine.score(test_event)
            print(f"\n  📊 Scoring test event:")
            print(f"     • Score: {score:.2f}")
            print(f"     • Reasons: {reasons}")
            
            return True
        else:
            print(f"❌ testuser not in baselines")
            return False
            
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def check_storage():
    """Check storage paths."""
    print("\n" + "="*70)
    print("📁 Storage Path Check")
    print("="*70)
    
    paths = {
        "Auth Event Store": CONFIG.auth_event_store,
        "Baseline Store": CONFIG.baseline_store,
        "Event Store": CONFIG.event_store,
        "Incident Store": CONFIG.incident_store,
    }
    
    for name, path in paths.items():
        exists = path.exists()
        status = "✓" if exists else "✗"
        size = ""
        if exists and path.is_file():
            size = f" ({path.stat().st_size:,} bytes)"
        print(f"  {status} {name}: {path}{size}")
    
    return True


def main():
    """Run all validation tests."""
    print("\n" + "="*70)
    print("🔬 SentinelAI UEBA Validation Suite")
    print("="*70)
    
    # Check storage first
    check_storage()
    
    # Run component tests
    results = []
    results.append(("Storage", check_storage()))
    results.append(("UEBA Transformer", test_ueba_transformer()))
    results.append(("UEBA Filter", test_ueba_filter()))
    results.append(("UEBA Baseline", test_ueba_baseline()))
    
    # Auth collector is Windows-only, test if available
    if CONFIG.os_platform == "windows":
        results.append(("Windows Auth Collector", test_auth_collector()))
    else:
        print(f"\n⏭️  Skipping Windows Auth Collector (platform: {CONFIG.os_platform})")
    
    # Summary
    print("\n" + "="*70)
    print("📊 Validation Summary")
    print("="*70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ PASS" if result else "❌ FAIL"
        print(f"  {status}: {name}")
    
    print(f"\nResult: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n✅ All validation tests passed!")
        return 0
    else:
        print(f"\n❌ {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
