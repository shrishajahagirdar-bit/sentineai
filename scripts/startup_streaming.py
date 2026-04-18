#!/usr/bin/env python3
"""
SentinelAI Real-Time Streaming - Startup Orchestrator
=====================================================

One-command startup for complete real-time pipeline:
Kafka → Consumer → EventBuffer → WebSocket → Dashboard

Manages:
1. Kafka broker (via docker-compose)
2. Kafka consumer service
3. WebSocket server
4. Streamlit dashboard

Usage:
    python scripts/startup_streaming.py [--mode all|kafka|consumer|websocket|dashboard]
    
Examples:
    # Start all services
    python scripts/startup_streaming.py

    # Start only Kafka and WebSocket (dashboard manual)
    python scripts/startup_streaming.py --mode kafka websocket

    # Start only dashboard (assumes other services running)
    python scripts/startup_streaming.py --mode dashboard
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s"
)
logger = logging.getLogger(__name__)


class ServiceManager:
    """Manages startup and teardown of all services."""
    
    def __init__(self, project_root: Path):
        """Initialize service manager.
        
        Args:
            project_root: Root directory of SentinelAI project
        """
        self.project_root = project_root
        self.processes: dict[str, subprocess.Popen] = {}
    
    def start_kafka(self) -> bool:
        """Start Kafka broker using docker-compose.
        
        Returns:
            True if started successfully
        """
        logger.info("\n" + "="*70)
        logger.info("Starting Kafka Broker...")
        logger.info("="*70)
        
        try:
            # Check if docker-compose.yml exists
            compose_file = self.project_root / "docker-compose.yml"
            if not compose_file.exists():
                logger.error(f"❌ docker-compose.yml not found at {compose_file}")
                return False
            
            # Start Kafka
            result = subprocess.run(
                ["docker-compose", "-f", str(compose_file), "up", "-d", "kafka", "zookeeper"],
                cwd=str(self.project_root),
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                logger.error(f"❌ Failed to start Kafka: {result.stderr}")
                return False
            
            logger.info("✅ Kafka container started")
            
            # Wait for Kafka to be ready
            logger.info("Waiting for Kafka to be ready...")
            for attempt in range(30):
                try:
                    result = subprocess.run(
                        ["docker-compose", "-f", str(compose_file), "exec", "-T", "kafka",
                         "kafka-broker-api-versions.sh", "--bootstrap-server", "localhost:9092"],
                        cwd=str(self.project_root),
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    if result.returncode == 0:
                        logger.info("✅ Kafka is ready")
                        return True
                
                except:
                    pass
                
                logger.info(f"  Waiting... (attempt {attempt+1}/30)")
                time.sleep(2)
            
            logger.error("❌ Kafka failed to become ready")
            return False
        
        except Exception as e:
            logger.error(f"❌ Error starting Kafka: {e}")
            return False
    
    def start_kafka_consumer(self) -> bool:
        """Start Kafka consumer service.
        
        Returns:
            True if started successfully
        """
        logger.info("\n" + "="*70)
        logger.info("Starting Kafka Consumer Service...")
        logger.info("="*70)
        
        try:
            script = """
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from kafka.kafka_consumer_service import start_consumer_service
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | KafkaConsumer | %(message)s"
)

if start_consumer_service():
    print("\\n✅ Kafka Consumer Service started successfully")
    import signal
    signal.pause()
else:
    print("\\n❌ Failed to start Kafka Consumer Service")
    sys.exit(1)
"""
            
            process = subprocess.Popen(
                [sys.executable, "-c", script],
                cwd=str(self.project_root),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            self.processes["kafka_consumer"] = process
            logger.info("✅ Kafka Consumer Service started")
            
            # Give it a moment to initialize
            time.sleep(2)
            
            return True
        
        except Exception as e:
            logger.error(f"❌ Error starting Kafka Consumer: {e}")
            return False
    
    def start_windows_stream_processor(self) -> bool:
        """Start Windows telemetry stream processor.
        
        Returns:
            True if started successfully
        """
        logger.info("\n" + "="*70)
        logger.info("Starting Windows Stream Processor...")
        logger.info("="*70)
        
        try:
            script_path = self.project_root / "scripts" / "run_windows_stream_processor.py"
            if not script_path.exists():
                logger.error(f"❌ Windows stream processor script not found: {script_path}")
                return False
            
            # Start stream processor
            process = subprocess.Popen(
                [sys.executable, str(script_path)],
                cwd=str(self.project_root),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            self.processes["windows_stream_processor"] = process
            logger.info("✅ Windows Stream Processor started")
            
            # Give it a moment to initialize
            time.sleep(2)
            
            return True
        
        except Exception as e:
            logger.error(f"❌ Error starting Windows Stream Processor: {e}")
            return False
    
    def start_websocket_server(self) -> bool:
        """Start WebSocket server using uvicorn.
        
        Returns:
            True if started successfully
        """
        logger.info("\n" + "="*70)
        logger.info("Starting WebSocket Server...")
        logger.info("="*70)
        
        try:
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m", "uvicorn",
                    "backend.websocket_server:app",
                    "--host", "0.0.0.0",
                    "--port", "8001",
                    "--log-level", "info",
                ],
                cwd=str(self.project_root),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            self.processes["websocket_server"] = process
            
            # Wait for server to start
            logger.info("Waiting for WebSocket server to be ready...")
            for attempt in range(30):
                try:
                    result = subprocess.run(
                        ["curl", "-s", "http://localhost:8001/health"],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    if result.returncode == 0:
                        logger.info("✅ WebSocket Server is ready")
                        logger.info(f"   Endpoint: ws://localhost:8001/ws/events/{{tenant_id}}")
                        return True
                
                except:
                    pass
                
                logger.info(f"  Waiting... (attempt {attempt+1}/30)")
                time.sleep(1)
            
            logger.error("❌ WebSocket server failed to start")
            return False
        
        except Exception as e:
            logger.error(f"❌ Error starting WebSocket server: {e}")
            return False
    
    def start_dashboard(self) -> bool:
        """Start Streamlit dashboard.
        
        Returns:
            True if started successfully
        """
        logger.info("\n" + "="*70)
        logger.info("Starting Streamlit Dashboard...")
        logger.info("="*70)
        
        try:
            # Use app_streaming.py (real-time version)
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m", "streamlit",
                    "run", "dashboard/app_streaming.py",
                    "--logger.level=info",
                ],
                cwd=str(self.project_root),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            self.processes["dashboard"] = process
            logger.info("✅ Streamlit Dashboard started")
            logger.info("   Local URL: http://localhost:8501")
            
            return True
        
        except Exception as e:
            logger.error(f"❌ Error starting dashboard: {e}")
            return False
    
    def start_test_producer(self) -> bool:
        """Start test event producer.
        
        Returns:
            True if started successfully
        """
        logger.info("\n" + "="*70)
        logger.info("Starting Test Event Producer...")
        logger.info("="*70)
        
        try:
            process = subprocess.Popen(
                [
                    sys.executable,
                    "scripts/test_kafka_producer.py",
                    "--continuous",
                    "--interval", "0.01",
                    "--count", "100",
                ],
                cwd=str(self.project_root),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            self.processes["test_producer"] = process
            logger.info("✅ Test Producer started (continuous mode)")
            
            return True
        
        except Exception as e:
            logger.error(f"❌ Error starting test producer: {e}")
            return False
    
    def print_status(self) -> None:
        """Print status of all services."""
        logger.info("\n" + "="*70)
        logger.info("SERVICE STATUS")
        logger.info("="*70)
        
        services = {
            "Kafka Broker": "docker-compose (localhost:9092)",
            "Windows Stream Processor": "windows-telemetry → scored-events",
            "Kafka Consumer": "Running (consuming from scored-events topic)",
            "WebSocket Server": "http://localhost:8001 | ws://localhost:8001/ws/events/{tenant_id}",
            "Streamlit Dashboard": "http://localhost:8501",
            "Test Producer": "Publishing 100 events every 60s",
        }
        
        for service, info in services.items():
            status = "✅" if service.replace(" ", "_").lower() in self.processes else "   "
            logger.info(f"{status} {service:<25} {info}")
        
        logger.info("="*70)
    
    def cleanup(self) -> None:
        """Cleanup and shutdown all services."""
        logger.info("\n" + "="*70)
        logger.info("Shutting down all services...")
        logger.info("="*70)
        
        for name, process in self.processes.items():
            try:
                logger.info(f"Stopping {name}...")
                process.terminate()
                process.wait(timeout=5)
                logger.info(f"✅ {name} stopped")
            except subprocess.TimeoutExpired:
                logger.warning(f"Force killing {name}...")
                process.kill()
            except Exception as e:
                logger.error(f"Error stopping {name}: {e}")
        
        logger.info("✅ All services stopped")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="SentinelAI Real-Time Streaming - Service Startup"
    )
    parser.add_argument(
        "--mode",
        nargs="+",
        default=["all"],
        choices=["all", "kafka", "consumer", "stream_processor", "websocket", "dashboard", "producer"],
        help="Services to start"
    )
    parser.add_argument(
        "--no-producer",
        action="store_true",
        help="Skip starting test producer"
    )
    
    args = parser.parse_args()
    
    project_root = Path(__file__).parent.parent
    manager = ServiceManager(project_root)
    
    print("\n" + "="*70)
    print("SentinelAI Real-Time Event Streaming Platform")
    print("="*70)
    print("Starting services...")
    print("="*70 + "\n")
    
    try:
        modes = args.mode
        if "all" in modes:
            modes = ["kafka", "stream_processor", "consumer", "websocket", "dashboard", "producer"]
        
        if "kafka" in modes:
            if not manager.start_kafka():
                logger.error("Failed to start Kafka, aborting")
                return 1
        
        if "stream_processor" in modes:
            if not manager.start_windows_stream_processor():
                logger.warning("Failed to start Windows Stream Processor")
        
        if "consumer" in modes:
            if not manager.start_kafka_consumer():
                logger.warning("Failed to start Kafka Consumer")
        
        if "websocket" in modes:
            if not manager.start_websocket_server():
                logger.warning("Failed to start WebSocket Server")
        
        if "producer" in modes and not args.no_producer:
            manager.start_test_producer()
        
        if "dashboard" in modes:
            if not manager.start_dashboard():
                logger.warning("Failed to start Dashboard")
        
        manager.print_status()
        
        logger.info("\n🟢 All services started successfully!")
        logger.info("\nNext steps:")
        logger.info("1. Open browser: http://localhost:8501 (Dashboard)")
        logger.info("2. Check WebSocket health: curl http://localhost:8001/health")
        logger.info("3. Monitor Kafka: kafka-console-consumer.sh --bootstrap-server localhost:9092 --topic security-logs")
        logger.info("\nPress Ctrl+C to shutdown all services...\n")
        
        # Keep running
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        logger.info("\n❌ Interrupted by user")
    
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}")
        return 1
    
    finally:
        manager.cleanup()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
