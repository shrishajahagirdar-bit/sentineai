# Real-Time Attack Timeline API Reference

Complete REST API documentation for the SentinelAI timeline replay system.

---

## Base URL

```
http://localhost:8001
```

---

## Authentication

All requests require the following header:
```
Authorization: Bearer <token>
```

---

## Response Format

All responses are JSON with the following structure:

**Success (2xx)**:
```json
{
  "status": "success",
  "data": { ... },
  "timestamp": "2026-04-18T10:00:00Z"
}
```

**Error (4xx, 5xx)**:
```json
{
  "status": "error",
  "error": "Error message",
  "timestamp": "2026-04-18T10:00:00Z"
}
```

---

## Timeline Events API

### Add Event

**Endpoint**: `POST /timeline/events/add`

**Description**: Add a new event to the timeline

**Request Body**:
```json
{
  "timestamp": "2026-04-18T10:00:00Z",
  "event_id": "evt_001",
  "tenant_id": "acme_corp",
  "host_id": "server_01",
  "user_id": "admin",
  "process_id": "pid_1234",
  "parent_process_id": "pid_sys",
  "process_name": "powershell.exe",
  "event_type": "process_create",
  "severity": "critical",
  "source": "edr_agent",
  "mitre_techniques": ["T1086", "T1068"],
  "mitre_tactics": ["execution", "privilege-escalation"],
  "details": {
    "command_line": "powershell.exe -NoProfile -Command...",
    "exit_code": 0
  }
}
```

**Response**:
```json
{
  "status": "success",
  "data": {
    "event_id": "evt_001",
    "added_at": "2026-04-18T10:00:01Z"
  }
}
```

**cURL Example**:
```bash
curl -X POST http://localhost:8001/timeline/events/add \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer token123" \
  -d '{
    "timestamp": "2026-04-18T10:00:00Z",
    "event_id": "evt_001",
    "tenant_id": "acme_corp",
    "host_id": "server_01",
    "event_type": "process_create",
    "severity": "critical",
    "source": "edr_agent",
    "process_name": "powershell.exe"
  }'
```

---

### Get Event

**Endpoint**: `GET /timeline/events/{event_id}`

**Description**: Retrieve a specific event

**Query Parameters**:
- `tenant_id` (required): Tenant ID

**Response**:
```json
{
  "status": "success",
  "data": {
    "event_id": "evt_001",
    "timestamp": "2026-04-18T10:00:00Z",
    "process_name": "powershell.exe",
    "event_type": "process_create",
    "severity": "critical",
    "host_id": "server_01",
    "user_id": "admin"
  }
}
```

**cURL Example**:
```bash
curl "http://localhost:8001/timeline/events/evt_001?tenant_id=acme_corp" \
  -H "Authorization: Bearer token123"
```

---

### Query Time Range

**Endpoint**: `POST /timeline/events/query-range`

**Description**: Query events within a time range

**Request Body**:
```json
{
  "tenant_id": "acme_corp",
  "start_time": "2026-04-18T09:00:00Z",
  "end_time": "2026-04-18T11:00:00Z",
  "filters": {
    "host_id": "server_01",
    "severity": "critical",
    "event_type": "process_create",
    "mitre_technique": "T1068"
  }
}
```

**Response**:
```json
{
  "status": "success",
  "data": {
    "count": 5,
    "events": [
      {
        "event_id": "evt_001",
        "timestamp": "2026-04-18T10:00:00Z",
        "process_name": "powershell.exe",
        "severity": "critical"
      }
    ]
  }
}
```

**cURL Example**:
```bash
curl -X POST http://localhost:8001/timeline/events/query-range \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer token123" \
  -d '{
    "tenant_id": "acme_corp",
    "start_time": "2026-04-18T09:00:00Z",
    "end_time": "2026-04-18T11:00:00Z",
    "filters": {"severity": "critical"}
  }'
```

---

## Timeline Replay API

### Load for Replay

**Endpoint**: `POST /timeline/replay/load`

**Description**: Load events into replay engine

**Request Body**:
```json
{
  "tenant_id": "acme_corp",
  "start_time": "2026-04-18T09:00:00Z",
  "end_time": "2026-04-18T11:00:00Z",
  "filters": {
    "host_id": "server_01",
    "severity": "critical"
  }
}
```

**Response**:
```json
{
  "status": "success",
  "data": {
    "events_loaded": 42,
    "start_time": "2026-04-18T10:00:00Z",
    "end_time": "2026-04-18T10:30:00Z"
  }
}
```

---

### Play

**Endpoint**: `POST /timeline/replay/play`

**Description**: Start or resume timeline playback

**Request Body**:
```json
{
  "speed": 2.0
}
```

**Parameters**:
- `speed` (optional): Playback speed (0.5 to 5.0, default 1.0)

**Response**:
```json
{
  "status": "success",
  "data": {
    "state": "playing",
    "speed": 2.0
  }
}
```

**cURL Example**:
```bash
curl -X POST http://localhost:8001/timeline/replay/play \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer token123" \
  -d '{"speed": 2.0}'
```

---

### Pause

**Endpoint**: `POST /timeline/replay/pause`

**Description**: Pause timeline playback

**Response**:
```json
{
  "status": "success",
  "data": {
    "state": "paused",
    "current_timestamp": "2026-04-18T10:15:00Z",
    "current_index": 21,
    "total_events": 42
  }
}
```

**cURL Example**:
```bash
curl -X POST http://localhost:8001/timeline/replay/pause \
  -H "Authorization: Bearer token123"
```

---

### Stop

**Endpoint**: `POST /timeline/replay/stop`

**Description**: Stop timeline playback and reset

**Response**:
```json
{
  "status": "success",
  "data": {
    "state": "stopped"
  }
}
```

---

### Step Forward

**Endpoint**: `POST /timeline/replay/step-forward`

**Description**: Advance timeline by N events

**Query Parameters**:
- `count` (optional): Number of events to advance (default 1)

**Response**:
```json
{
  "status": "success",
  "data": {
    "event": {
      "event_id": "evt_005",
      "timestamp": "2026-04-18T10:05:00Z",
      "process_name": "cmd.exe",
      "event_type": "process_create"
    },
    "current_index": 5,
    "total_events": 42
  }
}
```

**cURL Example**:
```bash
curl -X POST "http://localhost:8001/timeline/replay/step-forward?count=5" \
  -H "Authorization: Bearer token123"
```

---

### Step Backward

**Endpoint**: `POST /timeline/replay/step-backward`

**Description**: Rewind timeline by N events

**Query Parameters**:
- `count` (optional): Number of events to rewind (default 1)

**Response**: (Same as step-forward)

---

### Jump to Timestamp

**Endpoint**: `POST /timeline/replay/jump-to`

**Description**: Jump to nearest event at specific timestamp

**Request Body**:
```json
"2026-04-18T10:30:00Z"
```

**Response**:
```json
{
  "status": "success",
  "data": {
    "event": {
      "event_id": "evt_030",
      "timestamp": "2026-04-18T10:30:05Z",
      "process_name": "explorer.exe"
    },
    "current_index": 30,
    "total_events": 42
  }
}
```

**cURL Example**:
```bash
curl -X POST http://localhost:8001/timeline/replay/jump-to \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer token123" \
  -d '"2026-04-18T10:30:00Z"'
```

---

### Get Playback Stats

**Endpoint**: `GET /timeline/replay/stats`

**Description**: Get current playback status

**Query Parameters**:
- `tenant_id` (required): Tenant ID

**Response**:
```json
{
  "status": "success",
  "data": {
    "play_state": "playing",
    "playback_speed": 2.0,
    "events_processed": 25,
    "total_events": 42,
    "progress_percent": 59.5,
    "current_timestamp": "2026-04-18T10:15:00Z"
  }
}
```

**cURL Example**:
```bash
curl "http://localhost:8001/timeline/replay/stats?tenant_id=acme_corp" \
  -H "Authorization: Bearer token123"
```

---

### Set Filter

**Endpoint**: `POST /timeline/replay/filter`

**Description**: Apply filter during replay

**Request Body**:
```json
{
  "filter_key": "severity",
  "filter_value": "critical"
}
```

**Response**:
```json
{
  "status": "success",
  "data": {
    "filter_applied": true,
    "events_matching": 18
  }
}
```

---

## Attack Chain Correlation API

### Correlate Events

**Endpoint**: `POST /timeline/correlate/events`

**Description**: Correlate specific events into attack chain

**Request Body**:
```json
{
  "tenant_id": "acme_corp",
  "event_ids": ["evt_001", "evt_002", "evt_003", "evt_004", "evt_005"],
  "chain_id": "chain_001"
}
```

**Response**:
```json
{
  "status": "success",
  "data": {
    "chain_id": "chain_001",
    "total_events": 5,
    "severity": "critical",
    "anomaly_score": 92.5,
    "kill_chain_progression": [
      {"phase": "reconnaissance", "timestamp": "2026-04-18T10:00:00Z"},
      {"phase": "delivery", "timestamp": "2026-04-18T10:05:00Z"},
      {"phase": "exploitation", "timestamp": "2026-04-18T10:10:00Z"}
    ],
    "tags": ["critical_threat", "multi_stage_attack", "privilege_escalation"]
  }
}
```

**cURL Example**:
```bash
curl -X POST http://localhost:8001/timeline/correlate/events \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer token123" \
  -d '{
    "tenant_id": "acme_corp",
    "event_ids": ["evt_001", "evt_002", "evt_003"]
  }'
```

---

### Correlate by Process Tree

**Endpoint**: `POST /timeline/correlate/process-tree`

**Description**: Correlate events by process tree

**Request Body**:
```json
{
  "tenant_id": "acme_corp",
  "root_process_id": "pid_1234",
  "start_time": "2026-04-18T09:00:00Z",
  "end_time": "2026-04-18T11:00:00Z",
  "chain_id": "chain_proc_001"
}
```

**Response**: (Same as correlate events)

---

### Get Attack Chain

**Endpoint**: `GET /timeline/attack-chains/{chain_id}`

**Description**: Retrieve specific attack chain

**Response**:
```json
{
  "status": "success",
  "data": {
    "chain_id": "chain_001",
    "tenant_id": "acme_corp",
    "root_process_id": "pid_1234",
    "total_events": 7,
    "severity": "critical",
    "anomaly_score": 92.5,
    "tags": ["critical_threat", "multi_stage_attack"],
    "kill_chain_progression": [
      {
        "phase": "reconnaissance",
        "timestamp": "2026-04-18T10:00:00Z"
      }
    ],
    "events": [
      {
        "event_id": "evt_001",
        "timestamp": "2026-04-18T10:00:00Z",
        "process_name": "powershell.exe",
        "event_type": "process_create",
        "severity": "critical",
        "anomaly_score": 85.0,
        "mitre_techniques": ["T1086", "T1068"],
        "kill_chain_phase": "reconnaissance"
      }
    ]
  }
}
```

---

### List All Chains

**Endpoint**: `GET /timeline/attack-chains`

**Description**: List all attack chains for tenant

**Query Parameters**:
- `tenant_id` (required): Tenant ID

**Response**:
```json
{
  "status": "success",
  "data": {
    "count": 3,
    "chains": [
      {
        "chain_id": "chain_001",
        "severity": "critical",
        "total_events": 7,
        "anomaly_score": 92.5
      }
    ]
  }
}
```

**cURL Example**:
```bash
curl "http://localhost:8001/timeline/attack-chains?tenant_id=acme_corp" \
  -H "Authorization: Bearer token123"
```

---

### Get Chains by Severity

**Endpoint**: `GET /timeline/attack-chains/severity/{severity}`

**Description**: Get attack chains by severity level

**Path Parameters**:
- `severity`: critical, high, medium, low

**Query Parameters**:
- `tenant_id` (required): Tenant ID

**Response**:
```json
{
  "status": "success",
  "data": {
    "severity": "critical",
    "count": 2,
    "chains": [
      {
        "chain_id": "chain_001",
        "total_events": 7,
        "anomaly_score": 92.5
      }
    ]
  }
}
```

**cURL Example**:
```bash
curl "http://localhost:8001/timeline/attack-chains/severity/critical?tenant_id=acme_corp" \
  -H "Authorization: Bearer token123"
```

---

## Timeline Statistics API

### Get Statistics

**Endpoint**: `GET /timeline/stats`

**Description**: Get timeline statistics

**Query Parameters**:
- `tenant_id` (required): Tenant ID

**Response**:
```json
{
  "status": "success",
  "data": {
    "tenant_id": "acme_corp",
    "total_events": 523,
    "event_types": {
      "process_create": 245,
      "network_connection": 156,
      "file_access": 89,
      "registry_write": 33
    },
    "severity_distribution": {
      "critical": 45,
      "high": 123,
      "medium": 267,
      "low": 88
    },
    "last_event_timestamp": "2026-04-18T10:59:59Z",
    "earliest_event_timestamp": "2026-04-17T09:00:00Z"
  }
}
```

---

### Clear Timeline

**Endpoint**: `POST /timeline/clear`

**Description**: Clear all events (admin only)

**Query Parameters**:
- `tenant_id` (required): Tenant ID

**Response**:
```json
{
  "status": "success",
  "data": {
    "cleared": true,
    "events_deleted": 523
  }
}
```

**⚠️ CAUTION**: This operation cannot be undone.

---

## Error Responses

### 400 Bad Request

```json
{
  "status": "error",
  "error": "Missing required field: tenant_id"
}
```

### 401 Unauthorized

```json
{
  "status": "error",
  "error": "Invalid or missing authorization token"
}
```

### 404 Not Found

```json
{
  "status": "error",
  "error": "Event not found: evt_001"
}
```

### 500 Internal Server Error

```json
{
  "status": "error",
  "error": "Internal server error occurred"
}
```

---

## Rate Limiting

- **Default**: 1000 requests per minute per tenant
- **Burst**: Up to 100 requests per second
- **Headers**: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`

---

## Best Practices

1. **Use batch operations**: Add multiple events in a single request when possible
2. **Filter wisely**: Apply filters to reduce data volume
3. **Archive old timelines**: Export and clear timelines older than 30 days
4. **Monitor stats**: Regularly check timeline stats to optimize queries
5. **Use appropriate time ranges**: Smaller ranges = faster queries
6. **Implement retry logic**: Handle transient failures gracefully

---

## Integration Examples

### Python with Requests

```python
import requests

BASE_URL = "http://localhost:8001"
TOKEN = "your_token_here"
HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}

# Add event
event = {
    "timestamp": "2026-04-18T10:00:00Z",
    "event_id": "evt_001",
    "tenant_id": "acme_corp",
    "process_name": "powershell.exe",
    "event_type": "process_create",
    "severity": "critical"
}
response = requests.post(f"{BASE_URL}/timeline/events/add", 
                        json=event, headers=HEADERS)

# Query timeline
query = {
    "tenant_id": "acme_corp",
    "start_time": "2026-04-18T09:00:00Z",
    "end_time": "2026-04-18T11:00:00Z"
}
response = requests.post(f"{BASE_URL}/timeline/events/query-range",
                        json=query, headers=HEADERS)

# Get stats
response = requests.get(f"{BASE_URL}/timeline/stats?tenant_id=acme_corp",
                       headers=HEADERS)
```

### JavaScript/Node.js

```javascript
const fetch = require('node-fetch');

const baseUrl = 'http://localhost:8001';
const token = 'your_token_here';
const headers = {
  'Authorization': `Bearer ${token}`,
  'Content-Type': 'application/json'
};

// Load timeline and play
async function playTimeline() {
  // Load
  let res = await fetch(`${baseUrl}/timeline/replay/load`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      tenant_id: 'acme_corp',
      start_time: '2026-04-18T09:00:00Z',
      end_time: '2026-04-18T11:00:00Z'
    })
  });
  
  // Play
  res = await fetch(`${baseUrl}/timeline/replay/play`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ speed: 2.0 })
  });
  
  let data = await res.json();
  console.log(`Playing at ${data.data.speed}x speed`);
}
```

---

## Webhooks (Optional)

Configure webhooks for event notifications:

```json
{
  "event_type": "attack_chain_detected",
  "webhook_url": "https://your-system.com/webhooks/timeline",
  "tenant_id": "acme_corp",
  "min_severity": "high"
}
```

---

## Support

- **Documentation**: See [TIMELINE_REPLAY_GUIDE.md](TIMELINE_REPLAY_GUIDE.md)
- **Demo**: Run `python scripts/timeline_demo.py`
- **Issues**: Create an issue in the project repository

---

**Version**: 1.0 Timeline API  
**Last Updated**: April 18, 2026  
**Status**: Production Ready ✅
