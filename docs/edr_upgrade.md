## SentinelAI EDR Upgrade Design

### New Deep Telemetry Collectors

- `agent/collector/sysmon_collector.py`
- `agent/collector/etw_collector.py`
- `agent/collector/linux_audit_collector.py`

### Windows

Sysmon coverage:

- process creation
- network connections
- file modifications
- registry changes

ETW layer:

- high-level ETW streaming abstraction
- process injection signal hook
- suspicious execution chain signal emission

### Linux

- auditd log ingestion
- syslog ingestion
- process + network tracking reuse existing collectors

### Behavioral Detection Goals

- process tree reconstruction
- anomalous parent-child lineage
- suspicious execution chain analysis
- deeper host telemetry beyond basic process/network polling
