from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kafka.producer import SecurityLogsProducer
from kafka.topics import KafkaTopics
from sentinel_config import CONFIG


def main() -> None:
    producer = SecurityLogsProducer(topic=KafkaTopics.TENANT_EVENTS)
    if not CONFIG.dead_letter_store.exists():
        print(json.dumps({"replayed": 0, "reason": "no_dlq_file"}))
        return

    lines = CONFIG.dead_letter_store.read_text(encoding="utf-8").splitlines()
    replayed = 0
    remaining: list[str] = []
    for line in lines:
        if not line.strip():
            continue
        payload = json.loads(line)
        payload.pop("dlq_reason", None)
        if producer.publish(payload, topic=KafkaTopics.TENANT_EVENTS):
            replayed += 1
        else:
            remaining.append(line)

    CONFIG.dead_letter_store.write_text("\n".join(remaining) + ("\n" if remaining else ""), encoding="utf-8")
    print(json.dumps({"replayed": replayed, "remaining": len(remaining)}))


if __name__ == "__main__":
    main()
