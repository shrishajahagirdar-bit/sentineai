from __future__ import annotations

from edr_behavior.correlation import BehavioralCorrelationEngine
from edr_behavior.kill_chain import infer_stage
from edr_behavior.mitre import map_to_mitre
from edr_behavior.process_tree import ProcessTreeReconstructor


class BehavioralEngine:
    def __init__(self) -> None:
        self.process_tree = ProcessTreeReconstructor()
        self.correlation = BehavioralCorrelationEngine()

    def analyze(self, event: dict) -> dict[str, object]:
        tree = self.process_tree.ingest(event) if str(event.get("event_type")) == "process_create" else {}
        correlation = self.correlation.ingest(event)
        mitre = map_to_mitre(event)
        kill_chain_stage = infer_stage(event)
        response = self._recommended_response(event, correlation)
        return {
            "process_tree": tree,
            "correlation": correlation,
            "mitre": mitre,
            "kill_chain_stage": kill_chain_stage,
            "recommended_response": response,
        }

    @staticmethod
    def _recommended_response(event: dict, correlation: dict[str, object]) -> dict[str, object]:
        severity = str(event.get("severity", "low")).lower()
        suspicious = bool(correlation.get("suspicious_chain"))
        if severity in {"high", "critical"} or suspicious:
            return {
                "action": "isolate_host",
                "mode": "simulated",
                "reason": "behavioral_chain_detected" if suspicious else "high_severity_event",
            }
        if str(event.get("event_type")) == "process_create":
            return {"action": "monitor_process", "mode": "safe", "reason": "lineage_tracking"}
        return {"action": "alert_only", "mode": "safe", "reason": "insufficient_context"}
