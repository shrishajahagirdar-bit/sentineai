from __future__ import annotations

import unittest

from agent.core.config import AgentConfig
from agent.core.normalizer import build_event, heartbeat_event
from agent.main import WindowsEDRAgent


class AgentPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = AgentConfig.load()

    def test_normalized_event_contains_required_fields(self) -> None:
        event = build_event(
            self.config,
            user="alice",
            event_source="process",
            event_type="process_create",
            raw_data={"parent_pid": 4},
            process_name="cmd.exe",
            pid=1234,
            cpu=1.5,
            memory=4096,
        )
        self.assertEqual(event["host"], self.config.hostname)
        self.assertEqual(event["machine_id"], self.config.machine_id)
        self.assertEqual(event["event_source"], "process")
        self.assertEqual(event["pid"], 1234)

    def test_heartbeat_event_uses_agent_schema(self) -> None:
        event = heartbeat_event(self.config, queue_depth=7)
        self.assertEqual(event["event_source"], "heartbeat")
        self.assertEqual(event["event_type"], "agent_heartbeat")
        self.assertEqual(event["raw_data"]["queue_depth"], 7)

    def test_agent_queue_drains_into_batch(self) -> None:
        agent = WindowsEDRAgent(config=self.config)
        agent.event_queue.put({"event_id": "1"})
        agent.event_queue.put({"event_id": "2"})
        batch = agent._drain_queue()
        self.assertEqual(len(batch), 2)


if __name__ == "__main__":
    unittest.main()
