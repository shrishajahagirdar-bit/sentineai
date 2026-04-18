#!/usr/bin/env python3
"""
Test Kafka Producer for Real-Time Streaming Demo
================================================

Publishes test security events to Kafka for testing the complete pipeline:
Kafka → Consumer → EventBuffer → WebSocket → Dashboard

Usage:
    python scripts/test_kafka_producer.py [--count 100] [--interval 0.1]
"""

from __future__ import annotations

import argparse
import json
import logging
import time
from datetime import datetime, timedelta
import random

from kafka import KafkaProducer
from kafka.errors import KafkaError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def generate_test_event(event_num: int) -> dict:
    """Generate a realistic test security event.
    
    Args:
        event_num: Event sequence number
        
    Returns:
        Test event dict
    """
    
    event_types = [
        "process_create",
        "network_connection",
        "file_access",
        "registry_modification",
        "user_login",
        "privilege_escalation",
        "lateral_movement",
        "credential_access",
    ]
    
    users = ["admin", "user1", "user2", "system", "NETWORK SERVICE"]
    hosts = ["DESKTOP-ABC123", "SERVER-01", "LAPTOP-XYZ", "DC-PRIMARY"]
    sources = [
        "sysmon",
        "windows_event",
        "auditd",
        "osquery",
        "velociraptor"
    ]
    
    severity_levels = ["low", "medium", "high", "critical"]
    
    # Bias towards lower severity (10% critical)
    if random.random() < 0.1:
        severity = "critical"
        risk_score = random.uniform(80, 100)
    elif random.random() < 0.2:
        severity = "high"
        risk_score = random.uniform(60, 80)
    elif random.random() < 0.4:
        severity = "medium"
        risk_score = random.uniform(40, 60)
    else:
        severity = "low"
        risk_score = random.uniform(0, 40)
    
    event_type = random.choice(event_types)
    
    # Generate realistic event
    event = {
        "timestamp": (datetime.utcnow() - timedelta(seconds=random.randint(0, 60))).isoformat() + "Z",
        "event_type": event_type,
        "source": random.choice(sources),
        "user": random.choice(users),
        "host": random.choice(hosts),
        "severity": severity,
        "risk_score": risk_score,
        "tenant_id": "default",
        
        # Event-specific details
        "process_id": random.randint(100, 10000),
        "parent_process_id": random.randint(1, 1000),
        "process_name": random.choice(["cmd.exe", "powershell.exe", "notepad.exe", "svchost.exe"]),
        "command_line": f"test_command_{event_num}",
        
        # Network details
        "source_ip": f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
        "destination_ip": f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}",
        "destination_port": random.choice([80, 443, 22, 445, 3389, 4444, random.randint(5000, 9999)]),
        
        # File details
        "file_path": f"C:\\Users\\test\\file_{event_num}.txt",
        "file_hash": f"sha256_{event_num:032x}",
        
        # Metadata
        "event_id": f"event_{event_num:010d}",
        "message": f"Test event #{event_num}: {event_type}",
    }
    
    return event


def create_producer(bootstrap_servers: list[str] = None) -> KafkaProducer:
    """Create Kafka producer.
    
    Args:
        bootstrap_servers: Kafka broker addresses
        
    Returns:
        KafkaProducer instance
    """
    bootstrap_servers = bootstrap_servers or ["localhost:9092"]
    
    try:
        producer = KafkaProducer(
            bootstrap_servers=bootstrap_servers,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            acks="all",
            retries=3,
            compression_type="snappy",
        )
        logger.info(f"✅ Kafka producer created: {bootstrap_servers}")
        return producer
    except Exception as e:
        logger.error(f"❌ Failed to create Kafka producer: {e}")
        raise


def publish_events(
    producer: KafkaProducer,
    topic: str = "security-logs",
    count: int = 100,
    interval: float = 0.1,
) -> int:
    """Publish test events to Kafka.
    
    Args:
        producer: KafkaProducer instance
        topic: Kafka topic name
        count: Number of events to publish
        interval: Delay between events (seconds)
        
    Returns:
        Number of successfully published events
    """
    
    published = 0
    failed = 0
    
    logger.info(f"Publishing {count} test events to topic '{topic}'...")
    logger.info(f"Interval: {interval}s | Total time: ~{count * interval:.1f}s")
    
    start_time = time.time()
    
    try:
        for i in range(count):
            try:
                event = generate_test_event(i)
                
                # Send to Kafka
                future = producer.send(topic, value=event)
                record_metadata = future.get(timeout=10)
                
                published += 1
                
                # Progress indicator
                if (i + 1) % 10 == 0:
                    elapsed = time.time() - start_time
                    rate = (i + 1) / elapsed if elapsed > 0 else 0
                    logger.info(
                        f"Progress: {i+1}/{count} | "
                        f"Rate: {rate:.1f} events/sec | "
                        f"Topic: {record_metadata.topic} | "
                        f"Partition: {record_metadata.partition}"
                    )
                
                # Delay between sends
                if interval > 0:
                    time.sleep(interval)
            
            except Exception as e:
                logger.error(f"Error publishing event {i}: {e}")
                failed += 1
        
        # Ensure all messages are sent
        producer.flush()
        elapsed = time.time() - start_time
        
        logger.info("=" * 70)
        logger.info(f"✅ Publishing complete!")
        logger.info(f"Published: {published}/{count} events")
        logger.info(f"Failed: {failed}")
        logger.info(f"Elapsed time: {elapsed:.2f}s")
        logger.info(f"Average rate: {published/elapsed:.1f} events/sec")
        logger.info("=" * 70)
        
        return published
    
    except KeyboardInterrupt:
        logger.info("❌ Interrupted by user")
        return published
    
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}")
        return published


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Publish test security events to Kafka"
    )
    parser.add_argument(
        "--bootstrap-servers",
        default="localhost:9092",
        help="Kafka bootstrap servers (comma-separated)"
    )
    parser.add_argument(
        "--topic",
        default="security-logs",
        help="Kafka topic name"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=100,
        help="Number of events to publish"
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=0.1,
        help="Delay between events (seconds)"
    )
    parser.add_argument(
        "--continuous",
        action="store_true",
        help="Publish events continuously until interrupted"
    )
    
    args = parser.parse_args()
    
    bootstrap_servers = [s.strip() for s in args.bootstrap_servers.split(",")]
    
    print("\n" + "=" * 70)
    print("SentinelAI Test Kafka Producer")
    print("=" * 70)
    print(f"Bootstrap servers: {bootstrap_servers}")
    print(f"Topic: {args.topic}")
    print(f"Event count: {args.count}")
    print(f"Interval: {args.interval}s")
    if args.continuous:
        print("Mode: CONTINUOUS")
    print("=" * 70 + "\n")
    
    try:
        producer = create_producer(bootstrap_servers)
        
        if args.continuous:
            batch = 0
            while True:
                logger.info(f"\n📤 Batch #{batch + 1}")
                publish_events(producer, args.topic, args.count, args.interval)
                batch += 1
                logger.info("Waiting before next batch...")
                time.sleep(60)
        else:
            publish_events(producer, args.topic, args.count, args.interval)
    
    except KeyboardInterrupt:
        logger.info("\n✅ Shutdown requested")
    
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}")
        return 1
    
    finally:
        if "producer" in locals():
            producer.close()
    
    return 0


if __name__ == "__main__":
    exit(main())
