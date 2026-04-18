from __future__ import annotations

import unittest

import pandas as pd

from collector.attack_simulator import AttackSimulator
from validation.dataset_checker import check_dataset
from validation.labels import attach_standard_labels, event_label, label_to_name
from ml_engine.features import events_to_frame


class TrainingPipelineTests(unittest.TestCase):
    def test_label_standardization(self) -> None:
        anomaly = attach_standard_labels({"event_type": "anomaly", "severity": "high", "metadata": {}})
        normal = attach_standard_labels({"event_type": "normal", "severity": "low", "metadata": {}})
        self.assertEqual(anomaly["label"], 1)
        self.assertEqual(normal["label"], 0)
        self.assertEqual(label_to_name(1), "anomaly")
        self.assertEqual(event_label({"attack_type": "brute_force", "metadata": {}}), 1)

    def test_attack_simulator_generates_mixed_labels(self) -> None:
        simulator = AttackSimulator(seed=42, attack_ratio=0.2)
        events = simulator.generate_stream(batch_size=20)
        labels = [event["label"] for event in events]
        self.assertGreater(sum(labels), 0)
        self.assertLess(sum(labels), len(events))

    def test_feature_frame_is_numeric(self) -> None:
        simulator = AttackSimulator(seed=42, attack_ratio=0.2)
        frame = events_to_frame(simulator.generate_stream(batch_size=10))
        self.assertIsInstance(frame, pd.DataFrame)
        self.assertTrue(all(str(dtype).startswith(("float", "int")) for dtype in frame.dtypes))

    def test_dataset_checker_warns_on_low_anomaly_ratio(self) -> None:
        features = [[0.0, 1.0]] * 10
        labels = [0] * 9 + [1]
        result = check_dataset(features, labels, minimum_samples=5)
        self.assertTrue(result.valid)
        self.assertIsNotNone(result.warning)


if __name__ == "__main__":
    unittest.main()
