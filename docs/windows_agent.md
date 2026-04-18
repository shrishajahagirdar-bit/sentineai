## SentinelAI Windows Agent

### Overview

The SentinelAI Windows agent is a lightweight endpoint telemetry sensor that:

- collects real process telemetry with `psutil`
- collects real network connection telemetry with `psutil`
- reads Windows Event Viewer logs with `pywin32`
- batches events every 1 second
- streams JSON telemetry to Kafka topic `endpoint-events`
- writes structured local logs to `logs/agent.log`

### Project Structure

```text
agent/
  collector/
    process_collector.py
    network_collector.py
    windows_event_collector.py
  core/
    config.py
    logging.py
    normalizer.py
    schema.py
  transport/
    kafka_producer.py
  main.py
```

### Requirements

Install dependencies from the repository root:

```powershell
pip install -r requirements.txt
```

Important packages:

- `psutil`
- `pywin32`
- `confluent-kafka`

### Windows Run Instructions

Start Kafka first, then run the agent from the repository root:

```powershell
python -m agent.main
```

Optional environment variables:

```powershell
$env:SENTINEL_AGENT_KAFKA_BOOTSTRAP="localhost:9092"
$env:SENTINEL_AGENT_KAFKA_TOPIC="endpoint-events"
$env:SENTINEL_AGENT_PROCESS_POLL_SECONDS="2"
$env:SENTINEL_AGENT_NETWORK_POLL_SECONDS="2"
$env:SENTINEL_AGENT_EVENT_POLL_SECONDS="2"
$env:SENTINEL_AGENT_BATCH_FLUSH_SECONDS="1"
$env:SENTINEL_AGENT_HEARTBEAT_SECONDS="10"
```

### Output Schema

Each event is normalized to:

```json
{
  "event_id": "uuid",
  "timestamp": "ISO-8601",
  "host": "hostname",
  "machine_id": "uuid",
  "session_name": "Console",
  "user": "username",
  "event_source": "process | network | windows_event | heartbeat",
  "event_type": "process_create | login | network_connection | system_event",
  "severity": "low | medium | high | critical",
  "raw_data": {},
  "process_name": "",
  "pid": 0,
  "cpu": 0.0,
  "memory": 0,
  "network": {},
  "event_log_id": "",
  "ml_score": 0.0
}
```

### Example Event

```json
{
  "event_id": "6e44fef9-d8be-45d7-a7f7-7d882ef64498",
  "timestamp": "2026-04-18T08:41:16.114102+00:00",
  "host": "WS-001",
  "machine_id": "a8e74b0c-a2c6-4e1d-8b96-d4fa6f3df7ba",
  "session_name": "Console",
  "user": "CORP\\alice",
  "event_source": "process",
  "event_type": "process_create",
  "severity": "low",
  "raw_data": {
    "creation_time": 1713429661.0,
    "parent_pid": 672
  },
  "process_name": "powershell.exe",
  "pid": 7248,
  "cpu": 1.4,
  "memory": 57815040,
  "network": {},
  "event_log_id": "",
  "ml_score": 0.0
}
```

### Notes

- The agent is read-only and does not kill processes, alter files, or modify the registry.
- Windows Security log visibility depends on local privileges and audit policy.
- Sysmon channel support is attempted when enabled, but only works if Sysmon is installed and exposing its operational log.
