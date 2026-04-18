from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kafka.producer import SecurityLogsProducer
from kafka.topics import KafkaTopics


def main() -> None:
    producer = SecurityLogsProducer(topic=KafkaTopics.TENANT_EVENTS)
    tenant_id = "load-test-tenant"
    published = 0
    for idx in range(10_000):
        payload = {
            "event_id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tenant_id": tenant_id,
            "hostname": "load-host-01",
            "source": "network",
            "event_type": "network_connection",
            "severity": "medium",
            "raw_log": f"simulated load event {idx}",
            "parsed_fields": {"remote_ip": f"203.0.113.{idx % 250}", "packet_rate": 1200 + idx},
            "ml_score": 0.0,
            "ml_prediction": "unknown",
            "metadata": {"host_id": "load-host-01"},
            "user": "svc-load",
        }
        if producer.publish(payload, topic=KafkaTopics.TENANT_EVENTS):
            published += 1
    print(json.dumps({"published": published, "tenant_id": tenant_id}))


if __name__ == "__main__":
    main()
