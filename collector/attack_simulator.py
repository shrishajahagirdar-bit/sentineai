from __future__ import annotations

from datetime import datetime, timedelta, timezone
import random
from typing import Any
from uuid import uuid4

import numpy as np

from validation.labels import attach_standard_labels


class AttackSimulator:
    def __init__(self, seed: int = 42, attack_ratio: float = 0.20) -> None:
        self.random = random.Random(seed)
        self.np_random = np.random.default_rng(seed)
        self.attack_ratio = attack_ratio
        self.users = ["alice", "bob", "charlie", "diana", "eve"]
        self.devices = ["ws-01", "ws-02", "srv-01", "db-01", "vpn-01"]
        self.base_time = datetime.now(timezone.utc)
        self.attack_types = ["brute_force", "ddos", "insider_threat"]

    def generate_stream(self, batch_size: int) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        if batch_size <= 0:
            return events

        anomaly_count = max(1, int(round(batch_size * self.attack_ratio)))
        anomaly_count = min(anomaly_count, batch_size)
        normal_count = max(0, batch_size - anomaly_count)

        schedule = [(0, "normal")] * normal_count
        for idx in range(anomaly_count):
            schedule.append((1, self.attack_types[idx % len(self.attack_types)]))

        self.random.shuffle(schedule)
        for _, attack_type in schedule:
            event_type, label = self.assign_event_type(attack_type=attack_type)
            if label == 0:
                events.append(self._normal_event())
            elif attack_type == "brute_force":
                events.append(self._brute_force_event())
            elif attack_type == "ddos":
                events.append(self._ddos_event())
            else:
                events.append(self._insider_threat_event())

        return events

    def _timestamp(self, seconds_offset: int = 0) -> str:
        self.base_time += timedelta(seconds=max(1, seconds_offset or 1))
        return self.base_time.isoformat()

    def assign_event_type(self, attack_type: str | None = None) -> tuple[str, int]:
        selected_attack = attack_type or self.random.choice(self.attack_types)
        if selected_attack == "normal":
            return "normal", 0
        return "anomaly", 1

    def _base_event(self, *, source: str, event_type: str, severity: str, raw_log: str, parsed_fields: dict[str, Any], attack_type: str) -> dict[str, Any]:
        user = str(parsed_fields.get("user_id", parsed_fields.get("username", self.random.choice(self.users))))
        event = {
            "event_id": str(uuid4()),
            "timestamp": self._timestamp(self.random.randint(1, 5)),
            "source": source,
            "event_type": event_type,
            "severity": severity,
            "status": "ok",
            "user": user,
            "raw_log": raw_log,
            "parsed_fields": parsed_fields,
            "attack_type": attack_type,
            "ml_score": 1.0 if event_type == "anomaly" else 0.0,
            "ml_prediction": event_type,
            "metadata": {
                "device_id": parsed_fields.get("device_id", self.random.choice(self.devices)),
                "attack_type": attack_type,
                "simulated": True,
            },
        }
        return attach_standard_labels(event)

    def _normal_event(self) -> dict[str, Any]:
        user = self.random.choice(self.users)
        device = self.random.choice(self.devices)
        source = self.random.choice(["system", "app", "network"])
        return self._base_event(
            source=source,
            event_type="normal",
            severity="low",
            raw_log=f"Normal {source} activity observed for {user}",
            parsed_fields={
                "user_id": user,
                "device_id": device,
                "ip_address": f"10.0.0.{self.random.randint(2, 200)}",
                "cpu_percent": float(self.np_random.normal(18, 5)),
                "memory_rss": float(self.np_random.normal(220_000_000, 40_000_000)),
            },
            attack_type="none",
        )

    def _brute_force_event(self) -> dict[str, Any]:
        user = self.random.choice(self.users)
        ip = f"203.0.113.{self.random.randint(5, 200)}"
        failure_count = self.random.randint(6, 14)
        return self._base_event(
            source="auth",
            event_type="anomaly",
            severity="critical" if failure_count >= 10 else "high",
            raw_log=f"Repeated failed login attempts for {user} from {ip}",
            parsed_fields={
                "username": user,
                "ip_address": ip,
                "login_failure_count": failure_count,
                "time_window_spike": failure_count * 2,
                "burst_window_seconds": 60,
            },
            attack_type="brute_force",
        )

    def _ddos_event(self) -> dict[str, Any]:
        service_target = self.random.choice(["api", "login", "server"])
        source_ips = [f"198.51.100.{self.random.randint(1, 254)}" for _ in range(8)]
        packet_rate = int(self.np_random.integers(6_000, 15_000))
        return self._base_event(
            source="network",
            event_type="anomaly",
            severity="critical",
            raw_log=f"DDoS-like burst targeting {service_target}",
            parsed_fields={
                "source_ips": source_ips,
                "packet_rate": packet_rate,
                "bandwidth_usage": float(packet_rate * self.random.uniform(0.8, 1.8)),
                "service_target": service_target,
                "connection_spike_factor": float(self.random.uniform(4.0, 9.0)),
            },
            attack_type="ddos",
        )

    def _insider_threat_event(self) -> dict[str, Any]:
        user = self.random.choice(self.users)
        resource = self.random.choice(["payroll.xlsx", "finance.db", "hr_records.zip"])
        return self._base_event(
            source="system",
            event_type="anomaly",
            severity="high",
            raw_log=f"Unusual after-hours access for {user} on {resource}",
            parsed_fields={
                "user_id": user,
                "resource_accessed": resource,
                "access_time_anomaly": True,
                "privilege_level_change": bool(self.random.randint(0, 1)),
                "download_volume_mb": float(self.random.uniform(250, 1500)),
            },
            attack_type="insider_threat",
        )
