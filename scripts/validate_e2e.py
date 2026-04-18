from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kafka.consumer import SecurityLogsConsumer
from kafka.producer import SecurityLogsProducer
from kafka.topics import KafkaTopics


def build_event(tenant_id: str, host_id: str, idx: int) -> dict:
    return {
        "event_id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tenant_id": tenant_id,
        "hostname": host_id,
        "source": "windows_event" if idx % 3 == 0 else "process",
        "event_type": "login_failure" if idx % 5 == 0 else "process_create",
        "severity": "high" if idx % 7 == 0 else "medium",
        "raw_log": f"validation event {idx}",
        "raw_data": {"parent_pid": 100 + (idx % 10)},
        "parsed_fields": {"remote_ip": f"198.51.100.{idx % 200}"},
        "process_name": "powershell.exe",
        "pid": 2000 + idx,
        "cpu": 3.4,
        "memory": 204800,
        "network": {"remote_port": 443},
        "event_log_id": f"event-{idx}",
        "ml_score": 0.0,
        "ml_prediction": "unknown",
        "metadata": {"host_id": host_id},
        "user": f"user-{idx % 4}",
    }


def main() -> None:
    producer = SecurityLogsProducer(topic=KafkaTopics.TENANT_EVENTS)
    consumer = SecurityLogsConsumer(topic=KafkaTopics.TENANT_EVENTS, group_id="validation")
    tenant_id = "validation-tenant"
    for idx in range(1000):
        producer.publish(build_event(tenant_id, f"host-{idx % 10}", idx), topic=KafkaTopics.TENANT_EVENTS)
    processed = consumer.poll(max_messages=1000)
    print(json.dumps({"published": 1000, "processed": len(processed), "tenant_id": tenant_id}, indent=2))


if __name__ == "__main__":
    main()
