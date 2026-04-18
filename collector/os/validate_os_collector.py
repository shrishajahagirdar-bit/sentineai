#!/usr/bin/env python3
"""
OS Collector Validation Script

Tests the OS telemetry collector module to ensure it works correctly
with real Windows Event Logs and process monitoring.

Usage:
    python -m collector.os.validate_os_collector

Tests:
- Windows Event Log access and parsing
- Process monitoring via psutil
- Event normalization
- Daemon operation
- Pipeline integration
"""

from __future__ import annotations

import sys
import time
from datetime import datetime, timezone

from core.safe_wrapper import log_health_event
from sentinel_config import CONFIG

# Import OS collector modules
try:
    from .windows_event_collector import WindowsEventCollector
    from .process_monitor import ProcessMonitor
    from .unified_telemetry_format import UnifiedTelemetryFormat
    from .collector_daemon import CollectorDaemon
    from .pipeline_integration import PipelineIntegration, create_event_callback
except ImportError as e:
    print(f"ERROR: Failed to import OS collector modules: {e}")
    sys.exit(1)


def test_windows_event_collector():
    """Test Windows Event Log collector."""
    print("\n=== Testing Windows Event Collector ===")

    collector = WindowsEventCollector()
    print(f"Collector status: {collector.get_status()}")

    # Test single collection
    try:
        events = collector.collect_once(max_events=5)
        print(f"Collected {len(events)} events")

        if events:
            print("Sample event:")
            for key, value in events[0].items():
                if key != "raw_data":  # Skip raw data for brevity
                    print(f"  {key}: {value}")

        return True
    except Exception as e:
        print(f"ERROR: Windows Event Collector test failed: {e}")
        return False


def test_process_monitor():
    """Test process monitoring."""
    print("\n=== Testing Process Monitor ===")

    monitor = ProcessMonitor()
    print(f"Monitor status: {monitor.get_status()}")

    # Test telemetry collection
    try:
        events = monitor.collect_telemetry()
        print(f"Collected {len(events)} process events")

        if events:
            print("Sample process event:")
            for key, value in events[0].items():
                if key != "raw_data":  # Skip raw data for brevity
                    print(f"  {key}: {value}")

        # Test snapshot
        snapshot = monitor.get_process_snapshot()
        print(f"Process snapshot: {len(snapshot.get('sample_processes', []))} processes")

        return True
    except Exception as e:
        print(f"ERROR: Process Monitor test failed: {e}")
        return False


def test_unified_telemetry_format():
    """Test telemetry normalization."""
    print("\n=== Testing Unified Telemetry Format ===")

    # Create sample raw events
    raw_events = [
        {
            "event_id": 4624,
            "user": "DOMAIN\\testuser",
            "timestamp": "2024-01-15T09:30:00Z",
            "process": "C:\\Windows\\System32\\cmd.exe",
            "source": "windows_event_collector",
        },
        {
            "sub_event_type": "process_creation",
            "user": "testuser",
            "pid": 1234,
            "process": "notepad.exe",
            "cpu_percent": 5.0,
            "source": "process_monitor",
        }
    ]

    try:
        # Test normalization
        normalized = UnifiedTelemetryFormat.normalize_events(raw_events)
        print(f"Normalized {len(normalized)} events")

        for i, event in enumerate(normalized):
            print(f"Normalized event {i+1}:")
            print(f"  event_type: {event.get('event_type')}")
            print(f"  category: {event.get('category')}")
            print(f"  sub_event_type: {event.get('sub_event_type')}")
            print(f"  risk_score: {event.get('risk_score')}")

            # Validate event
            is_valid = UnifiedTelemetryFormat.validate_normalized_event(event)
            print(f"  valid: {is_valid}")

        return len(normalized) == len(raw_events)
    except Exception as e:
        print(f"ERROR: Unified Telemetry Format test failed: {e}")
        return False


def test_collector_daemon():
    """Test collector daemon."""
    print("\n=== Testing Collector Daemon ===")

    # Create event callback for testing
    collected_events = []

    def test_callback(events):
        collected_events.extend(events)
        print(f"Callback received {len(events)} events")

    daemon = CollectorDaemon(
        event_callback=test_callback,
        poll_interval_seconds=2.0,  # Fast polling for testing
        max_events_per_cycle=10,
    )

    print(f"Daemon status: {daemon.get_stats()}")

    try:
        # Start daemon
        if not daemon.start():
            print("ERROR: Failed to start daemon")
            return False

        print("Daemon started, waiting for events...")

        # Wait for a few collection cycles
        time.sleep(6)  # Should get 2-3 collection cycles

        # Stop daemon
        if not daemon.stop():
            print("ERROR: Failed to stop daemon")
            return False

        print(f"Daemon stopped. Collected {len(collected_events)} total events")
        print(f"Final stats: {daemon.get_stats()}")

        return len(collected_events) > 0
    except Exception as e:
        print(f"ERROR: Collector Daemon test failed: {e}")
        daemon.stop()  # Ensure cleanup
        return False


def test_pipeline_integration():
    """Test pipeline integration."""
    print("\n=== Testing Pipeline Integration ===")

    # Create pipeline with test settings
    pipeline = PipelineIntegration(
        kafka_enabled=False,  # Disable for testing
        ml_integration_enabled=False,  # Disable for testing
        dashboard_enabled=False,  # Disable for testing
        batch_size=5,
        flush_interval_seconds=2.0,
    )

    # Create sample events
    sample_events = [
        {
            "event_type": "os_telemetry",
            "category": "auth",
            "sub_event_type": "login_success",
            "user": "DOMAIN\\testuser",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        {
            "event_type": "os_telemetry",
            "category": "process",
            "sub_event_type": "process_creation",
            "user": "testuser",
            "process": "cmd.exe",
            "pid": 1234,
        }
    ]

    try:
        # Process events
        success = pipeline.process_events(sample_events)
        print(f"Pipeline processing success: {success}")

        # Force flush
        flush_success = pipeline.force_flush()
        print(f"Pipeline flush success: {flush_success}")

        # Get stats
        stats = pipeline.get_stats()
        print(f"Pipeline stats: {stats}")

        # Shutdown
        pipeline.shutdown()

        return success and flush_success
    except Exception as e:
        print(f"ERROR: Pipeline Integration test failed: {e}")
        return False


def run_full_validation():
    """Run complete validation suite."""
    print("=== OS Collector Validation Suite ===")
    print(f"Started at: {datetime.now(timezone.utc).isoformat()}")

    tests = [
        ("Windows Event Collector", test_windows_event_collector),
        ("Process Monitor", test_process_monitor),
        ("Unified Telemetry Format", test_unified_telemetry_format),
        ("Collector Daemon", test_collector_daemon),
        ("Pipeline Integration", test_pipeline_integration),
    ]

    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
            status = "PASS" if result else "FAIL"
            print(f"\n{test_name}: {status}")
        except Exception as e:
            print(f"\n{test_name}: ERROR - {e}")
            results.append((test_name, False))

    # Summary
    print("\n=== Validation Summary ===")
    passed = 0
    total = len(results)

    for test_name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"{test_name}: {status}")
        if result:
            passed += 1

    print(f"\nOverall: {passed}/{total} tests passed")

    if passed == total:
        print("✅ All tests passed! OS Collector is ready for production.")
        return True
    else:
        print("❌ Some tests failed. Check logs for details.")
        return False


if __name__ == "__main__":
    try:
        success = run_full_validation()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\nValidation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error during validation: {e}")
        sys.exit(1)