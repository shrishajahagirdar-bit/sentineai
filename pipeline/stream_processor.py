from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any

from collector.storage import append_jsonl
from core.schema import CanonicalEvent
from core.validator import validate_model
from edr_behavior.engine import BehavioralEngine
from ml_engine.online_learning import OnlineLearningEngine
from risk_engine.alert_generator import AlertGenerator
from risk_engine.scoring_engine import ScoringEngine
from sentinel_config import CONFIG
from validation.labels import normalize_label


class StreamProcessor:
    def __init__(self) -> None:
        self.online_learning = OnlineLearningEngine(
            feature_order=[
                "login_frequency",
                "ip_change_frequency",
                "request_rate",
                "severity_score",
                "hour_fraction",
                "minute_fraction",
                "is_after_hours",
                "source_auth",
                "source_network",
                "attack_weight",
            ]
        )
        self.scoring_engine = ScoringEngine()
        self.alert_generator = AlertGenerator()
        self.behavior_engine = BehavioralEngine()
        self.user_events: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=120))
        self.user_ips: dict[str, deque[str]] = defaultdict(lambda: deque(maxlen=20))
        self.user_hours: dict[str, deque[int]] = defaultdict(lambda: deque(maxlen=50))

    def process_event(self, raw_event: dict[str, Any], *, persist: bool = True) -> dict[str, Any]:
        event = validate_model(raw_event, CanonicalEvent, fallback={"event_type": "fallback"})
        enriched = self._enrich_event(event)
        features = self.extract_features(enriched)

        prediction = self.online_learning.predict(features)
        enriched["ml_score"] = prediction.ml_score
        enriched["ml_prediction"] = prediction.prediction
        enriched["frequency"] = features["request_rate"]
        enriched["user_behavior_score"] = round(
            min((features["login_frequency"] * 0.5) + (features["ip_change_frequency"] * 0.5), 1.0),
            4,
        )

        scoring = self.scoring_engine.score(enriched).to_dict()
        alert = self.alert_generator.generate(enriched, scoring)
        behavior = self.behavior_engine.analyze(enriched)

        enriched["risk_score"] = scoring["risk_score"]
        enriched["severity"] = scoring["severity"]
        enriched["anomaly_score"] = prediction.ml_score
        enriched["stream_features"] = features
        enriched["behavior"] = behavior

        update = self.online_learning.update(features, normalize_label(enriched))
        result = {
            "event": enriched,
            "features": features,
            "scoring": scoring,
            "alert": alert,
            "behavior": behavior,
            "online_learning": {
                "updated": update.updated,
                "model_version": update.model_version,
                "drift_detected": update.drift_detected,
                "fallback_triggered": update.fallback_triggered,
                "baseline_error": update.baseline_error,
                "recent_error": update.recent_error,
                "message": update.message,
            },
        }

        if persist:
            append_jsonl(CONFIG.event_store, enriched)
            if alert["alert"]:
                append_jsonl(CONFIG.incident_store, {**enriched, **alert})
        return result

    def extract_features(self, event: dict[str, Any]) -> dict[str, float]:
        user = str(event.get("user", "unknown"))
        parsed_fields = event.get("parsed_fields", {})
        if not isinstance(parsed_fields, dict):
            parsed_fields = {}

        event_ts = self._to_epoch(event.get("timestamp"))
        self.user_events[user].append(event_ts)
        current_ip = str(
            event.get("remote_ip")
            or parsed_fields.get("ip_address")
            or parsed_fields.get("source_ip")
            or "unknown"
        )
        self.user_ips[user].append(current_ip)

        dt = datetime.fromtimestamp(event_ts, tz=timezone.utc)
        self.user_hours[user].append(dt.hour)

        login_frequency = self._events_in_window(self.user_events[user], event_ts, window_seconds=900) / 15.0
        request_rate = self._events_in_window(self.user_events[user], event_ts, window_seconds=60) / 10.0
        ip_change_frequency = self._ip_change_frequency(self.user_ips[user])
        severity_score = self._severity_score(str(event.get("severity", "low")))
        attack_weight = self._attack_weight(str(event.get("attack_type", "none")))

        return {
            "login_frequency": round(min(login_frequency, 1.0), 4),
            "ip_change_frequency": round(ip_change_frequency, 4),
            "request_rate": round(min(request_rate, 1.0), 4),
            "severity_score": severity_score,
            "hour_fraction": round(dt.hour / 23.0 if dt.hour else 0.0, 4),
            "minute_fraction": round(dt.minute / 59.0 if dt.minute else 0.0, 4),
            "is_after_hours": 1.0 if dt.hour < 6 or dt.hour > 20 else 0.0,
            "source_auth": 1.0 if str(event.get("source", "")).lower() == "auth" else 0.0,
            "source_network": 1.0 if str(event.get("source", "")).lower() == "network" else 0.0,
            "attack_weight": attack_weight,
        }

    def _enrich_event(self, event: dict[str, Any]) -> dict[str, Any]:
        payload = dict(event)
        parsed_fields = payload.get("parsed_fields", {})
        if not isinstance(parsed_fields, dict):
            parsed_fields = {}

        if "remote_ip" not in payload and "ip_address" in parsed_fields:
            payload["remote_ip"] = parsed_fields["ip_address"]
        if "request_rate" not in payload and "packet_rate" in parsed_fields:
            try:
                payload["request_rate"] = min(float(parsed_fields["packet_rate"]) / 10000.0, 1.0)
            except (TypeError, ValueError):
                payload["request_rate"] = 0.0
        return payload

    @staticmethod
    def _to_epoch(value: Any) -> float:
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
        except ValueError:
            return datetime.now(timezone.utc).timestamp()

    @staticmethod
    def _events_in_window(history: deque[float], now_ts: float, *, window_seconds: int) -> int:
        return sum(1 for ts in history if now_ts - ts <= window_seconds)

    @staticmethod
    def _ip_change_frequency(history: deque[str]) -> float:
        if len(history) < 2:
            return 0.0
        changes = 0
        previous = None
        for ip in history:
            if previous is not None and ip != previous:
                changes += 1
            previous = ip
        return min(changes / max(len(history) - 1, 1), 1.0)

    @staticmethod
    def _severity_score(severity: str) -> float:
        return {
            "low": 0.25,
            "medium": 0.5,
            "high": 0.8,
            "critical": 1.0,
        }.get(severity.lower(), 0.25)

    @staticmethod
    def _attack_weight(attack_type: str) -> float:
        mapping = {
            "brute_force": 0.5,
            "ddos": 0.75,
            "insider_threat": 1.0,
            "insider": 1.0,
        }
        return mapping.get(attack_type.lower(), 0.0)
