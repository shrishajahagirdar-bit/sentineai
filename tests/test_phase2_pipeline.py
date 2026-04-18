from __future__ import annotations

import unittest

from risk_engine.incident_builder import IncidentBuilder
from storage.replay import replay_time_range


class Phase2PipelineTests(unittest.TestCase):
    def test_incident_builder_correlates_high_risk_events(self) -> None:
        builder = IncidentBuilder(window_minutes=10)
        event_one = {
            "event_id": "evt-1",
            "timestamp": "2026-04-18T10:00:00+00:00",
            "source": "system",
            "event_type": "login_failure",
            "user": "alice",
            "risk_score": 82,
            "severity": "high",
            "triggers": ["failed login attempts +20"],
        }
        event_two = {
            "event_id": "evt-2",
            "timestamp": "2026-04-18T10:05:00+00:00",
            "source": "system",
            "event_type": "login_failure",
            "user": "alice",
            "risk_score": 91,
            "severity": "critical",
            "triggers": ["failed login attempts +20"],
        }

        first = builder.process_event(event_one, persist=False)
        second = builder.process_event(event_two, persist=False)

        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        self.assertEqual(first["incident_id"], second["incident_id"])
        self.assertEqual(second["attack_type"], "bruteforce")
        self.assertEqual(len(second["related_event_ids"]), 2)

    def test_incident_builder_ignores_low_risk_noise(self) -> None:
        builder = IncidentBuilder(window_minutes=10)
        result = builder.process_event(
            {
                "event_id": "evt-noise",
                "timestamp": "2026-04-18T10:00:00+00:00",
                "source": "system",
                "event_type": "normal",
                "user": "alice",
                "risk_score": 10,
                "severity": "low",
            },
            persist=False,
        )
        self.assertIsNone(result)

    def test_replay_time_range_handles_bad_timestamps_safely(self) -> None:
        result = replay_time_range("bad-start", "bad-end", limit=10)
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
