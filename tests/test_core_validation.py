from __future__ import annotations

import unittest

from core.safe_wrapper import safe_execution
from core.schema import CanonicalEvent, MLOutputSchema, UIDataSchema
from core.transformers import normalize_event, normalize_ml_output, normalize_ui_payload, safe_dataframe_convert, safe_empty_check
from core.validator import enforce_types, fill_missing_fields, safe_cast, validate_model


class ValidationLayerTests(unittest.TestCase):
    def test_safe_cast_handles_wrong_types(self) -> None:
        self.assertEqual(safe_cast("12.5", float), 12.5)
        self.assertEqual(safe_cast("7", int), 7)
        self.assertEqual(safe_cast(None, dict), {})

    def test_fill_missing_fields(self) -> None:
        payload = fill_missing_fields({"user": "alice"}, {"risk_score": 0.0, "prediction": "unknown"})
        self.assertEqual(payload["risk_score"], 0.0)
        self.assertEqual(payload["prediction"], "unknown")

    def test_enforce_types_with_corrupted_values(self) -> None:
        schema = {"risk_score": float, "failed_attempts": int, "user": str}
        payload = enforce_types({"risk_score": "98.2", "failed_attempts": "3", "user": 12}, schema)
        self.assertEqual(payload["risk_score"], 98.2)
        self.assertEqual(payload["failed_attempts"], 3)
        self.assertEqual(payload["user"], "12")

    def test_validate_model_returns_fallback_for_bad_event(self) -> None:
        result = validate_model(None, CanonicalEvent, fallback={"event_type": "fallback"})
        self.assertEqual(result["event_type"], "fallback")
        self.assertEqual(result["risk_score"], 0.0)

    def test_normalize_ml_output_for_tuple(self) -> None:
        result = normalize_ml_output((0.88, 0.52), user="analyst")
        self.assertEqual(result["user"], "analyst")
        self.assertEqual(result["prediction"], "anomaly")

    def test_normalize_ml_output_for_corrupted_dict(self) -> None:
        result = normalize_ml_output({"risk_score": "bad", "anomaly_score": None})
        self.assertEqual(result["risk_score"], 0.0)
        self.assertEqual(result["anomaly_score"], 0.0)

    def test_normalize_event_handles_missing_fields(self) -> None:
        result = normalize_event({"user": "alice"})
        self.assertEqual(result["user"], "alice")
        self.assertIn("timestamp", result)
        self.assertIn("event_id", result)

    def test_normalize_ui_payload_handles_nulls(self) -> None:
        result = normalize_ui_payload({"metrics": None, "alerts": None, "logs": None, "risk_trend": None})
        self.assertEqual(result["metrics"], {})
        self.assertEqual(result["alerts"], [])

    def test_safe_dataframe_convert_and_empty_check(self) -> None:
        frame = safe_dataframe_convert({"records": [{"event_id": "1"}]})
        self.assertFalse(safe_empty_check(frame))
        self.assertTrue(safe_empty_check({}))

    def test_safe_execution_returns_safe_default(self) -> None:
        @safe_execution(default_factory=lambda: {"status": "safe_fallback", "message": "data unavailable", "risk_score": 0})
        def broken() -> dict[str, str]:
            raise RuntimeError("boom")

        result = broken()
        self.assertEqual(result["status"], "safe_fallback")


if __name__ == "__main__":
    unittest.main()
