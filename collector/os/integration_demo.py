#!/usr/bin/env python3
"""
OS Collector Integration Demo

Demonstrates how to integrate the OS telemetry collector with the existing
SentinelAI pipeline for real EDR capabilities.

Usage:
    python -m collector.os.integration_demo

Features:
- Starts OS telemetry collection
- Integrates with pipeline (Kafka/ML/Dashboard)
- Shows real-time event processing
- Graceful shutdown
"""

from __future__ import annotations

import signal
import sys
import time
from datetime import datetime, timezone

from core.safe_wrapper import log_health_event
from sentinel_config import CONFIG

# Import OS collector modules
from .collector_daemon import start_global_daemon, stop_global_daemon, get_global_daemon
from .pipeline_integration import create_event_callback, get_pipeline_integration


def demo_callback(events):
    """Demo callback to show received events."""
    print(f"\n📡 Received {len(events)} OS telemetry events:")

    for i, event in enumerate(events[:3], 1):  # Show first 3 events
        print(f"  {i}. {event.get('category', 'unknown')}/{event.get('sub_event_type', 'unknown')} - "
              f"User: {event.get('user', 'unknown')}, "
              f"Process: {event.get('process', 'unknown')}, "
              f"Risk: {event.get('risk_score', 0.0):.2f}")

    if len(events) > 3:
        print(f"  ... and {len(events) - 3} more events")


def run_integration_demo():
    """Run the OS collector integration demo."""
    print("🚀 SentinelAI OS Telemetry Collector Integration Demo")
    print("=" * 60)
    print(f"Started at: {datetime.now(timezone.utc).isoformat()}")
    print()

    # Setup signal handler for graceful shutdown
    def signal_handler(signum, frame):
        print("\n🛑 Shutdown signal received...")
        shutdown_demo()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        print("📋 Setting up pipeline integration...")

        # Get pipeline integration
        pipeline = get_pipeline_integration()
        print("✅ Pipeline integration ready")

        # Create event callback
        callback = create_event_callback()
        demo_callback_wrapper = lambda events: (callback(events), demo_callback(events))

        print("📡 Starting OS telemetry collection...")

        # Start the global daemon with demo callback
        if not start_global_daemon(
            event_callback=demo_callback_wrapper,
            poll_interval_seconds=3.0  # 3-second polling for demo
        ):
            print("❌ Failed to start OS collector daemon")
            return False

        print("✅ OS collector daemon started")
        print("🔄 Collecting real Windows OS telemetry...")
        print("   (Press Ctrl+C to stop)")
        print()

        # Monitor for a while
        start_time = time.time()
        while time.time() - start_time < 30:  # Run for 30 seconds
            time.sleep(1)

            # Show periodic stats
            daemon = get_global_daemon()
            pipeline_stats = pipeline.get_stats()

            if int(time.time() - start_time) % 10 == 0:  # Every 10 seconds
                print(f"\n📊 Stats at {int(time.time() - start_time)}s:")
                print(f"   Daemon: {daemon.get_stats()['events_collected']} events collected")
                print(f"   Pipeline: {pipeline_stats['events_processed']} events processed")

        print("\n⏰ Demo time limit reached")

    except KeyboardInterrupt:
        print("\n🛑 Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        return False
    finally:
        shutdown_demo()

    print("\n🎉 OS Collector Integration Demo completed successfully!")
    return True


def shutdown_demo():
    """Shutdown the demo gracefully."""
    print("🔄 Shutting down...")

    try:
        # Stop the daemon
        if stop_global_daemon():
            print("✅ OS collector daemon stopped")
        else:
            print("⚠️  OS collector daemon may not have stopped cleanly")

        # Get final stats
        pipeline = get_pipeline_integration()
        final_stats = pipeline.get_stats()

        print("\n📈 Final Statistics:")
        print(f"   Events Processed: {final_stats['events_processed']}")
        print(f"   Batches Flushed: {final_stats['batches_flushed']}")
        print(f"   Errors: {final_stats['errors_encountered']}")
        print(f"   Buffer Size: {final_stats['buffer_size']}")

        # Shutdown pipeline
        pipeline.shutdown()
        print("✅ Pipeline integration shutdown")

    except Exception as e:
        print(f"⚠️  Error during shutdown: {e}")


def show_configuration():
    """Show current configuration."""
    print("⚙️  Current Configuration:")
    print(f"   Poll Interval: 3.0 seconds")
    print(f"   Max Events/Cycle: 50")
    print(f"   Pipeline Batch Size: 10")
    print(f"   Flush Interval: 5.0 seconds")
    print()

    # Check integrations
    pipeline = get_pipeline_integration()
    integrations = pipeline.get_stats()['integrations']

    print("🔗 Integration Status:")
    print(f"   Kafka: {'✅ Enabled' if integrations['kafka'] else '❌ Disabled'}")
    print(f"   ML Engine: {'✅ Enabled' if integrations['ml_engine'] else '❌ Disabled'}")
    print(f"   Dashboard: {'✅ Enabled' if integrations['dashboard'] else '❌ Disabled'}")
    print()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--config":
        show_configuration()
    else:
        try:
            success = run_integration_demo()
            sys.exit(0 if success else 1)
        except KeyboardInterrupt:
            print("\n👋 Demo interrupted")
            sys.exit(0)
        except Exception as e:
            print(f"\n💥 Unexpected error: {e}")
            sys.exit(1)