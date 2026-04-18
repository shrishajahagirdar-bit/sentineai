from __future__ import annotations

import json
import time
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kafka.consumer import SecurityLogsConsumer


def main() -> None:
    consumer = SecurityLogsConsumer()
    while True:
        processed = consumer.poll(max_messages=50)
        if processed:
            print(json.dumps({"processed": len(processed), "sample": processed[:3]}, indent=2, default=str))
        time.sleep(1)


if __name__ == "__main__":
    main()
