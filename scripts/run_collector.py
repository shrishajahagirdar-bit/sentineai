from __future__ import annotations

import time

from collector.service import SentinelCollectorService
from sentinel_config import CONFIG


def main() -> None:
    service = SentinelCollectorService()
    service.start()

    try:
        while True:
            batch = service.collect_once()
            print(f"Published {len(batch)} real telemetry events")
            time.sleep(CONFIG.poll_interval_seconds)
    except KeyboardInterrupt:
        print("Stopping SentinelAI collector...")
    finally:
        service.shutdown()


if __name__ == "__main__":
    main()
