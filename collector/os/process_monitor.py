"""
Process Monitor - Real-time OS Process Telemetry

Uses psutil to monitor process creation, termination, and resource usage.
Provides real-time process telemetry for security monitoring.

Features:
- New process detection
- Process termination tracking
- CPU usage spikes monitoring
- Memory usage tracking
- Process hierarchy monitoring
- Safe user-mode operation

Output Format:
{
    "event_type": "os_telemetry",
    "category": "process",
    "sub_event_type": "process_creation | process_termination | cpu_spike",
    "user": "DOMAIN\\username",
    "host": "WORKSTATION-01",
    "timestamp": "2024-01-15T09:30:00Z",
    "process": "C:\\Windows\\System32\\cmd.exe",
    "pid": 1234,
    "parent_pid": 567,
    "cpu_percent": 85.5,
    "memory_mb": 150.2,
    "command_line": "cmd.exe /c echo hello",
    "risk_score": 0.0-1.0,
    "metadata": {...}
}
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, Set

from core.safe_wrapper import log_health_event
from sentinel_config import CONFIG

try:
    import psutil
except ImportError:
    psutil = None


class ProcessMonitor:
    """
    Real-time Process Monitoring using psutil

    Monitors process lifecycle and resource usage for security telemetry.
    Tracks process creation, termination, and performance anomalies.

    Safety Features:
    - User-mode only (no kernel access)
    - Graceful fallback if psutil unavailable
    - Memory-safe operation
    - Error handling for permission issues
    """

    def __init__(self) -> None:
        self.hostname = os.environ.get("COMPUTERNAME", "localhost")

        # Process tracking state
        self.known_processes: Dict[int, dict[str, Any]] = {}
        self.last_cpu_check = time.time()
        self.cpu_threshold = 80.0  # CPU usage threshold for alerts
        self.memory_threshold_mb = 500.0  # Memory usage threshold

        # Suspicious process patterns
        self.suspicious_patterns = [
            "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
            "rundll32.exe", "regsvr32.exe", "mshta.exe", "bitsadmin.exe"
        ]

        # Validate psutil availability
        if psutil is None:
            log_health_event(
                "warning",
                "process_monitor_init",
                "psutil not available; process monitoring disabled",
            )

    def collect_telemetry(self) -> list[dict[str, Any]]:
        """
        Collect current process telemetry.

        Returns:
            List of process-related telemetry events
        """
        if psutil is None:
            return []

        events: list[dict[str, Any]] = []

        try:
            # Get current processes
            current_processes = self._get_current_processes()

            # Detect new processes
            new_processes = self._detect_new_processes(current_processes)
            for proc_info in new_processes:
                event = self._create_process_event("process_creation", proc_info)
                if event:
                    events.append(event)

            # Detect terminated processes
            terminated_processes = self._detect_terminated_processes(current_processes)
            for proc_info in terminated_processes:
                event = self._create_process_event("process_termination", proc_info)
                if event:
                    events.append(event)

            # Check for CPU spikes
            cpu_spikes = self._detect_cpu_spikes(current_processes)
            for proc_info in cpu_spikes:
                event = self._create_process_event("cpu_spike", proc_info)
                if event:
                    events.append(event)

            # Update known processes
            self._update_known_processes(current_processes)

        except Exception as exc:
            log_health_event(
                "error",
                "process_monitor_collection",
                f"Failed to collect process telemetry: {str(exc)}",
            )

        return events

    def _get_current_processes(self) -> list[dict[str, Any]]:
        """Get information about all current processes."""
        processes = []

        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent',
                                           'memory_info', 'create_time', 'cmdline',
                                           'ppid']):
                try:
                    proc_info = proc.info

                    # Skip system processes we can't access
                    if proc_info['username'] is None:
                        continue

                    # Get additional process details
                    try:
                        memory_mb = proc_info['memory_info'].rss / (1024 * 1024) if proc_info['memory_info'] else 0
                        cmdline = ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else ''
                        create_time = datetime.fromtimestamp(proc_info['create_time'], timezone.utc).isoformat()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        continue

                    process_data = {
                        'pid': proc_info['pid'],
                        'name': proc_info['name'] or 'unknown',
                        'username': proc_info['username'] or 'unknown',
                        'cpu_percent': proc_info['cpu_percent'] or 0.0,
                        'memory_mb': round(memory_mb, 2),
                        'create_time': create_time,
                        'command_line': cmdline[:500],  # Truncate long command lines
                        'parent_pid': proc_info['ppid'],
                        'collected_at': datetime.now(timezone.utc).isoformat(),
                    }

                    processes.append(process_data)

                except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                    # Skip processes we can't access
                    continue

        except Exception as exc:
            log_health_event(
                "warning",
                "process_enumeration",
                f"Error enumerating processes: {str(exc)}",
            )

        return processes

    def _detect_new_processes(self, current_processes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Detect newly created processes."""
        new_processes = []

        current_pids = {proc['pid'] for proc in current_processes}

        for proc in current_processes:
            pid = proc['pid']
            if pid not in self.known_processes:
                new_processes.append(proc)

        return new_processes

    def _detect_terminated_processes(self, current_processes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Detect processes that have terminated."""
        terminated_processes = []

        current_pids = {proc['pid'] for proc in current_processes}

        for pid, proc_info in self.known_processes.items():
            if pid not in current_pids:
                # Process has terminated
                terminated_processes.append(proc_info)

        return terminated_processes

    def _detect_cpu_spikes(self, current_processes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Detect processes with high CPU usage."""
        cpu_spikes = []
        current_time = time.time()

        # Only check every few seconds to avoid false positives
        if current_time - self.last_cpu_check < 5.0:
            return cpu_spikes

        self.last_cpu_check = current_time

        for proc in current_processes:
            cpu_percent = proc.get('cpu_percent', 0.0)
            if cpu_percent > self.cpu_threshold:
                cpu_spikes.append(proc)

        return cpu_spikes

    def _update_known_processes(self, current_processes: list[dict[str, Any]]) -> None:
        """Update the known processes dictionary."""
        # Clear and rebuild from current snapshot
        self.known_processes.clear()

        for proc in current_processes:
            self.known_processes[proc['pid']] = proc.copy()

    def _create_process_event(self, event_type: str, proc_info: dict[str, Any]) -> dict[str, Any] | None:
        """Create a normalized telemetry event for a process."""
        try:
            # Determine risk score based on process characteristics
            risk_score = self._calculate_process_risk(proc_info, event_type)

            # Extract user (remove domain if present)
            username = proc_info.get('username', 'unknown')
            if '\\' in username:
                username = username.split('\\')[-1]

            # Build telemetry event
            event = {
                # Source identification
                "source": "process_monitor",
                "collector": "psutil_process_monitor",

                # Event classification
                "event_type": "os_telemetry",
                "category": "process",
                "sub_event_type": event_type,
                "severity": self._get_event_severity(event_type, risk_score),

                # Identity and location
                "user": username,
                "host": self.hostname,

                # Temporal
                "timestamp": proc_info.get('collected_at', datetime.now(timezone.utc).isoformat()),

                # Process details
                "process": proc_info.get('name', 'unknown'),
                "pid": proc_info.get('pid'),
                "parent_pid": proc_info.get('parent_pid'),
                "command_line": proc_info.get('command_line', ''),
                "create_time": proc_info.get('create_time'),

                # Resource usage
                "cpu_percent": proc_info.get('cpu_percent', 0.0),
                "memory_mb": proc_info.get('memory_mb', 0.0),

                # Risk assessment
                "risk_score": risk_score,

                # Metadata
                "metadata": {
                    "monitor": "process_monitor",
                    "psutil_available": psutil is not None,
                    "cpu_threshold": self.cpu_threshold,
                    "memory_threshold_mb": self.memory_threshold_mb,
                    "collected_at": datetime.now(timezone.utc).isoformat(),
                },
            }

            return event

        except Exception as exc:
            log_health_event(
                "debug",
                "process_event_creation",
                f"Failed to create process event: {str(exc)}",
            )
            return None

    def _calculate_process_risk(self, proc_info: dict[str, Any], event_type: str) -> float:
        """Calculate risk score for a process event."""
        risk_score = 0.0

        process_name = proc_info.get('name', '').lower()

        # High risk for suspicious process names
        if any(pattern.lower() in process_name for pattern in self.suspicious_patterns):
            risk_score += 0.4

        # High CPU usage
        if proc_info.get('cpu_percent', 0.0) > self.cpu_threshold:
            risk_score += 0.3

        # High memory usage
        if proc_info.get('memory_mb', 0.0) > self.memory_threshold_mb:
            risk_score += 0.2

        # Unknown parent process
        if proc_info.get('parent_pid') is None or proc_info.get('parent_pid') == 0:
            risk_score += 0.1

        # System user processes
        username = proc_info.get('username', '').lower()
        if any(sys_user in username for sys_user in ['system', 'local service', 'network service']):
            risk_score += 0.1

        # Process creation events are generally lower risk than spikes
        if event_type == "process_creation":
            risk_score *= 0.7
        elif event_type == "cpu_spike":
            risk_score *= 1.2

        return min(risk_score, 1.0)

    @staticmethod
    def _get_event_severity(event_type: str, risk_score: float) -> str:
        """Determine event severity based on type and risk score."""
        if event_type == "cpu_spike" or risk_score > 0.7:
            return "high"
        elif risk_score > 0.4:
            return "medium"
        else:
            return "low"

    def get_process_snapshot(self) -> dict[str, Any]:
        """Get current process snapshot for diagnostics."""
        if psutil is None:
            return {"error": "psutil not available"}

        try:
            processes = self._get_current_processes()
            return {
                "total_processes": len(processes),
                "known_processes": len(self.known_processes),
                "cpu_threshold": self.cpu_threshold,
                "memory_threshold_mb": self.memory_threshold_mb,
                "sample_processes": processes[:5],  # First 5 for debugging
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as exc:
            return {"error": str(exc)}

    def get_status(self) -> dict[str, Any]:
        """Get monitor status and statistics."""
        return {
            "monitor": "process_monitor",
            "available": psutil is not None,
            "known_processes": len(self.known_processes),
            "cpu_threshold": self.cpu_threshold,
            "memory_threshold_mb": self.memory_threshold_mb,
            "suspicious_patterns": self.suspicious_patterns.copy(),
            "last_cpu_check": self.last_cpu_check,
        }
