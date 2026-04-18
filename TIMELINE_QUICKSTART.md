# Timeline Replay System - Quick Start Guide

Get up and running with the Real-Time Attack Timeline Replay System in 5 minutes.

---

## 🚀 Installation

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

Required packages:
- `streamlit` - UI framework
- `plotly` - Interactive visualizations
- `pandas` - Data manipulation
- `networkx` - Graph processing
- `fastapi` - REST API
- `uvicorn` - ASGI server

### 2. Verify Installation

```bash
python -m py_compile edr_behavior/timeline_store.py
python -m py_compile edr_behavior/replay_engine.py
python -m py_compile edr_behavior/attack_chain_correlator.py
python -m py_compile backend/timeline_api.py
python -m py_compile dashboard/timeline_ui.py
python -m py_compile dashboard/timeline_viz.py
```

---

## 📊 Running the Demo

The demo shows all features of the timeline system:

```bash
cd c:\Users\SHRISHA\Desktop\HYD_3
python scripts/timeline_demo.py
```

**Demo Output**:
- ✅ 7 events added to timeline
- ✅ Timeline replay with step controls
- ✅ Attack chain correlation
- ✅ Kill chain progression (reconnaissance → exfiltration)
- ✅ Process tree reconstruction
- ✅ Forensic queries

**Expected Duration**: 5-10 seconds

---

## 🔌 REST API Setup

### Start FastAPI Server

```bash
uvicorn backend.websocket_server:app --host 0.0.0.0 --port 8001 --reload
```

Server runs at: `http://localhost:8001`

### Test API Endpoint

```bash
# Add an event
curl -X POST http://localhost:8001/timeline/events/add \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2026-04-18T10:00:00Z",
    "event_id": "test_001",
    "tenant_id": "test",
    "process_name": "powershell.exe",
    "event_type": "process_create",
    "severity": "critical"
  }'

# Get stats
curl http://localhost:8001/timeline/stats?tenant_id=test
```

---

## 💻 Streamlit UI Setup

### Start Streamlit Dashboard

```bash
streamlit run dashboard/app_streaming.py
```

Dashboard opens at: `http://localhost:8501`

### Using the Timeline Tab

1. Click **"Timeline"** tab
2. Select **"Forensic (Replay)"** mode
3. Set **Date Range** (e.g., last 24 hours)
4. Click **▶️ Play** to start replay
5. Use **⏸ Pause** to inspect events
6. **Step Forward/Backward** to navigate
7. **Jump to** specific time
8. Apply **Filters** (severity, host, process)

---

## 🔧 Basic Usage Examples

### Python: Adding Events

```python
from edr_behavior.timeline_store import TimelineEventStore, TimelineEvent, get_timeline_store
from datetime import datetime

# Get the timeline store
store = get_timeline_store()

# Create an event
event = TimelineEvent(
    timestamp=datetime.now().isoformat() + 'Z',
    event_id="attack_evt_001",
    tenant_id="my_org",
    host_id="prod_server_01",
    user_id="admin",
    process_id="pid_4567",
    parent_process_id="pid_explorer",
    process_name="cmd.exe",
    event_type="process_create",
    severity="critical",
    source="edr_agent",
    mitre_techniques=["T1086", "T1059"],
    mitre_tactics=["execution"],
    details={
        "command_line": "cmd.exe /c whoami",
        "parent": "explorer.exe"
    }
)

# Add to timeline
store.add_event(event)
```

### Python: Replaying Timeline

```python
from edr_behavior.replay_engine import get_replay_engine
from datetime import datetime, timedelta

# Get the replay engine
engine = get_replay_engine()

# Load timeline
count = engine.load_range(
    tenant_id="my_org",
    start_time=datetime.now() - timedelta(hours=1),
    end_time=datetime.now()
)
print(f"Loaded {count} events")

# Play at 2x speed
engine.play(speed=2.0)

# Pause and inspect
engine.pause()
stats = engine.get_stats()
print(f"Current event {stats.events_processed}/{stats.total_events}")

# Step through events
engine.step_forward(5)   # Skip 5 events ahead
engine.step_backward(2)  # Go back 2 events
engine.jump_to(datetime.now().isoformat() + 'Z')  # Jump to specific time
```

### Python: Correlating Events

```python
from edr_behavior.attack_chain_correlator import get_correlator
from edr_behavior.timeline_store import get_timeline_store
from datetime import datetime, timedelta

# Get services
store = get_timeline_store()
correlator = get_correlator()

# Query events
events = store.query_range(
    tenant_id="my_org",
    start_time=datetime.now() - timedelta(hours=1),
    end_time=datetime.now()
)

# Correlate into attack chain
if events:
    chain = correlator.correlate_events(
        tenant_id="my_org",
        events=events,
        chain_id="attack_chain_1"
    )
    
    print(f"Chain Severity: {chain.severity}")
    print(f"Anomaly Score: {chain.total_anomaly_score}")
    print(f"Kill Phases: {[p for p, _ in chain.kill_chain_progression]}")
    print(f"Tags: {chain.tags}")
```

### REST API: Full Workflow

```bash
#!/bin/bash

# Add event
curl -X POST http://localhost:8001/timeline/events/add \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2026-04-18T10:00:00Z",
    "event_id": "evt_001",
    "tenant_id": "acme",
    "process_name": "explorer.exe",
    "event_type": "process_create",
    "severity": "high",
    "host_id": "workstation_01"
  }'

# Query timeline
curl -X POST http://localhost:8001/timeline/events/query-range \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "acme",
    "start_time": "2026-04-18T09:00:00Z",
    "end_time": "2026-04-18T11:00:00Z",
    "filters": {"severity": "high"}
  }'

# Load for replay
curl -X POST http://localhost:8001/timeline/replay/load \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "acme",
    "start_time": "2026-04-18T09:00:00Z",
    "end_time": "2026-04-18T11:00:00Z"
  }'

# Play
curl -X POST http://localhost:8001/timeline/replay/play \
  -H "Content-Type: application/json" \
  -d '{"speed": 1.5}'

# Get stats
curl http://localhost:8001/timeline/replay/stats

# Correlate
curl -X POST http://localhost:8001/timeline/correlate/events \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "acme",
    "event_ids": ["evt_001", "evt_002"]
  }'
```

---

## 🎯 Common Tasks

### Task 1: Investigate Suspicious Process

```python
from edr_behavior.timeline_store import get_timeline_store
from datetime import datetime, timedelta

store = get_timeline_store()

# Find all events related to a process
tree = store.query_process_tree(
    tenant_id="my_org",
    process_id="suspicious_proc_id",
    start_time=datetime.now() - timedelta(hours=1),
    end_time=datetime.now(),
    include_children=True,
    include_parent=True
)

print(f"Root: {tree['process_name']}")
print(f"Parent: {tree['parent']['process_name'] if tree['parent'] else 'N/A'}")
for child_id, child in tree['children'].items():
    print(f"  └─ {child.process_name}")
```

### Task 2: Find Critical Events on Host

```python
from edr_behavior.timeline_store import get_timeline_store
from datetime import datetime, timedelta

store = get_timeline_store()

# Query critical events on specific host
critical_events = store.query_range(
    tenant_id="my_org",
    start_time=datetime.now() - timedelta(hours=24),
    end_time=datetime.now(),
    filters={
        'host_id': 'production_server_01',
        'severity': 'critical'
    }
)

for event in critical_events:
    print(f"[{event.severity}] {event.process_name} - {event.event_type}")
    print(f"  MITRE: {', '.join(event.mitre_techniques)}")
```

### Task 3: Analyze Attack Kill Chain

```python
from edr_behavior.attack_chain_correlator import get_correlator
from edr_behavior.timeline_store import get_timeline_store
from datetime import datetime, timedelta

store = get_timeline_store()
correlator = get_correlator()

# Get recent events and correlate
events = store.query_range(
    tenant_id="my_org",
    start_time=datetime.now() - timedelta(hours=1),
    end_time=datetime.now(),
    filters={'severity': 'critical'}
)

chain = correlator.correlate_events("my_org", events)

print(f"Severity: {chain.severity}")
print(f"Score: {chain.total_anomaly_score:.1f}/100")

print("\nKill Chain Progression:")
for phase, timestamp in chain.kill_chain_progression:
    print(f"  {phase.replace('_', ' ').title()} @ {timestamp}")

print("\nDetected Tags:")
for tag in chain.tags:
    print(f"  • {tag}")
```

### Task 4: Export Timeline for Analysis

```python
from edr_behavior.timeline_store import get_timeline_store
import json

store = get_timeline_store()

# Export all events to JSONL
store.export_jsonl("my_org", "timeline_export.jsonl")
print("✅ Exported timeline to timeline_export.jsonl")

# Export specific events
events = store.query_range("my_org", start_time, end_time)
with open("critical_events.jsonl", "w") as f:
    for event in events:
        f.write(json.dumps(event.__dict__) + "\n")
```

---

## 📚 File Reference

| File | Purpose | Key Classes |
|------|---------|-------------|
| `edr_behavior/timeline_store.py` | Event storage | `TimelineEventStore`, `TimelineEvent` |
| `edr_behavior/replay_engine.py` | Playback controls | `TimelineReplayEngine`, `PlayState` |
| `edr_behavior/attack_chain_correlator.py` | Event correlation | `AttackChainCorrelator`, `AttackChain` |
| `backend/timeline_api.py` | REST API | (FastAPI router) |
| `dashboard/timeline_ui.py` | Streamlit UI | (Render functions) |
| `dashboard/timeline_viz.py` | Visualizations | (Chart functions) |
| `scripts/timeline_demo.py` | Demo script | (Demo functions) |

---

## 🐛 Troubleshooting

### Issue: "No events found"
**Cause**: Events are stored in-memory and cleared when application restarts  
**Solution**: Use `import_jsonl()` to restore from backup

### Issue: "Query returns empty results"
**Cause**: Timestamp format mismatch or query range doesn't cover events  
**Solution**: Verify timestamps are ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ)

### Issue: "API returns 400 Bad Request"
**Cause**: Missing or invalid request parameters  
**Solution**: Check request body against API documentation

### Issue: "Streamlit app won't start"
**Cause**: Port 8501 already in use  
**Solution**: Use `streamlit run --logger.level=debug --server.port 8502 app.py`

---

## 📈 Performance Tips

1. **Use filters**: Reduce query scope with severity/host/event_type filters
2. **Limit time ranges**: Smaller ranges are faster to process
3. **Archive old events**: Clear timeline events older than 30 days
4. **Batch operations**: Add multiple events in single API calls
5. **Monitor memory**: Check `get_stats()` to avoid hitting memory limits

---

## 🔐 Security Notes

- Keep API tokens secure (use environment variables)
- Validate all input data before adding to timeline
- Implement rate limiting for public APIs
- Encrypt sensitive data in event details
- Audit all timeline access

---

## 📖 Next Steps

1. **Run the demo**: `python scripts/timeline_demo.py`
2. **Read the guide**: [TIMELINE_REPLAY_GUIDE.md](TIMELINE_REPLAY_GUIDE.md)
3. **Check API docs**: [TIMELINE_API_REFERENCE.md](TIMELINE_API_REFERENCE.md)
4. **Start the API**: `uvicorn backend.websocket_server:app --port 8001`
5. **Open the UI**: `streamlit run dashboard/app_streaming.py`

---

## 💡 Example Use Cases

- **Incident Response**: Replay attack timeline for forensic analysis
- **Threat Hunting**: Identify suspicious process chains and lateral movement
- **Security Testing**: Validate EDR detection and response capabilities
- **Compliance**: Document attack timelines for audit and regulatory requirements
- **Training**: Show analysts how attacks unfold in real-time

---

**Ready to get started?** Run the demo:
```bash
python scripts/timeline_demo.py
```

**Questions?** See the full documentation in [TIMELINE_REPLAY_GUIDE.md](TIMELINE_REPLAY_GUIDE.md)

---

**Version**: 1.0  
**Last Updated**: April 18, 2026  
**Status**: Production Ready ✅
