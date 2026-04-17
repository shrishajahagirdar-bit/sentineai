from __future__ import annotations

import time

from collector.service import SentinelCollectorService
from sentinel_config import CONFIG


def main() -> None:
    service = SentinelCollectorService()
    startup_events = service.start()
    if startup_events:
        for event in startup_events:
            print(f"[startup] {event['source']}: {event['message']}")

    try:
        while True:
            batch = service.collect_once()
            print(f"Collected {len(batch)} telemetry events")
            time.sleep(CONFIG.poll_interval_seconds)
    except KeyboardInterrupt:
        print("Stopping SentinelAI collector...")
    finally:
        service.shutdown()


if __name__ == "__main__":
    main()
