from __future__ import annotations

import unittest
from pathlib import Path

from resiliency.circuit_breaker import CircuitBreaker
from resiliency.spool import JsonlSpool


class ResiliencyTests(unittest.TestCase):
    def test_circuit_breaker_opens_after_threshold(self) -> None:
        breaker = CircuitBreaker(failure_threshold=2, recovery_timeout_seconds=60)
        self.assertTrue(breaker.allow())
        breaker.record_failure()
        self.assertTrue(breaker.allow())
        breaker.record_failure()
        self.assertFalse(breaker.allow())

    def test_jsonl_spool_round_trip(self) -> None:
        spool_path = Path("storage") / "test_spool.jsonl"
        try:
            spool = JsonlSpool(spool_path)
            spool.append({"event_id": "1"})
            spool.append({"event_id": "2"})
            drained = spool.drain(limit=10)
            self.assertEqual(len(drained), 2)
            self.assertEqual(spool.drain(limit=10), [])
        finally:
            if spool_path.exists():
                spool_path.unlink()


if __name__ == "__main__":
    unittest.main()
