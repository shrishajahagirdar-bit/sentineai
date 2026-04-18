from __future__ import annotations

import unittest

from edr_behavior.engine import BehavioralEngine


class BehaviorEngineTests(unittest.TestCase):
    def test_process_tree_and_execution_stage(self) -> None:
        engine = BehavioralEngine()
        result = engine.analyze(
            {
                "hostname": "host-1",
                "user": "alice",
                "event_type": "process_create",
                "severity": "medium",
                "pid": 200,
                "process_name": "powershell.exe",
                "raw_data": {"parent_pid": 100},
            }
        )
        self.assertEqual(result["kill_chain_stage"], "execution")
        self.assertEqual(result["mitre"]["technique"], "T1059")
        self.assertEqual(result["process_tree"]["parent_pid"], 100)

    def test_behavioral_correlation_flags_chain(self) -> None:
        engine = BehavioralEngine()
        events = [
            {"hostname": "host-2", "user": "bob", "event_type": "login_failure", "severity": "medium"},
            {"hostname": "host-2", "user": "bob", "event_type": "process_create", "severity": "high", "pid": 10, "raw_data": {"parent_pid": 1}},
            {"hostname": "host-2", "user": "bob", "event_type": "network_connection", "severity": "high"},
        ]
        last = {}
        for event in events:
            last = engine.analyze(event)
        self.assertTrue(last["correlation"]["suspicious_chain"])
        self.assertEqual(last["recommended_response"]["action"], "isolate_host")


if __name__ == "__main__":
    unittest.main()
