from __future__ import annotations

import unittest

from kafka.consumer import SecurityLogsConsumer
from kafka.producer import SecurityLogsProducer
from pipeline.stream_processor import StreamProcessor
from risk_engine.scoring_engine import ScoringEngine


class StreamingEngineTests(unittest.TestCase):
    def test_stream_processor_extracts_numeric_features(self) -> None:
        processor = StreamProcessor()
        result = processor.process_event(
            {
                "event_id": "evt-1",
                "timestamp": "2026-04-18T10:00:00+00:00",
                "source": "auth",
                "event_type": "anomaly",
                "severity": "high",
                "user": "alice",
                "attack_type": "brute_force",
                "parsed_fields": {
                    "ip_address": "203.0.113.10",
                    "login_failure_count": 8,
                    "access_time_anomaly": True,
                },
            },
            persist=False,
        )
        self.assertEqual(result["event"]["ml_prediction"], "anomaly")
        self.assertIn("request_rate", result["features"])
        self.assertGreaterEqual(result["scoring"]["risk_score"], 50)

    def test_scoring_engine_matches_expected_priority(self) -> None:
        scoring = ScoringEngine().score(
            {
                "event_id": "evt-2",
                "severity": "critical",
                "ml_score": 0.9,
                "user_behavior_score": 0.8,
                "attack_type": "insider_threat",
                "parsed_fields": {"access_time_anomaly": True},
            }
        )
        payload = scoring.to_dict()
        self.assertEqual(payload["severity"], "critical")
        self.assertTrue(payload["alert"])
        self.assertIn("insider_threat_detected", payload["reason"])

    def test_kafka_round_trip_uses_stream_processor(self) -> None:
        producer = SecurityLogsProducer()
        consumer = SecurityLogsConsumer()
        self.assertTrue(
            producer.publish(
                {
                    "event_id": "evt-3",
                    "timestamp": "2026-04-18T10:00:00+00:00",
                    "source": "network",
                    "event_type": "anomaly",
                    "severity": "critical",
                    "user": "svc-api",
                    "attack_type": "ddos",
                    "parsed_fields": {"packet_rate": 12000, "ip_address": "198.51.100.22"},
                }
            )
        )
        processed = consumer.poll(max_messages=1)
        self.assertEqual(len(processed), 1)
        self.assertIn("online_learning", processed[0])
        self.assertTrue(processed[0]["alert"]["alert"])


if __name__ == "__main__":
    unittest.main()
