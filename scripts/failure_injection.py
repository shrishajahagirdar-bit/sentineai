from __future__ import annotations

import json


def main() -> None:
    print(
        json.dumps(
            {
                "kafka_backpressure": "pause stream processor and validate spool + lag growth",
                "ml_failure": "remove model artifact and confirm heuristic fallback",
                "db_latency": "inject latency proxy and verify retries",
                "agent_disconnect": "stop heartbeat and verify degraded fleet state",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
