## SentinelAI Control Plane

### Overview

The control plane extends SentinelAI into a multi-tenant SaaS platform while preserving the existing data plane.

New modules:

```text
control_plane/
billing/
response_engine/
```

### FastAPI Endpoints

- `POST /auth/login`
- `POST /auth/refresh`
- `GET /tenants`
- `POST /tenants`
- `POST /tenants/{tenant_id}/users`
- `GET /agents`
- `POST /agents`
- `POST /agents/enroll`
- `POST /agents/{agent_id}/heartbeat`
- `GET /policies`
- `POST /policies`
- `GET /incidents`
- `POST /incidents`
- `GET /billing/usage`

### PostgreSQL + RLS

SQL bootstrap files:

- `control_plane/sql/schema.sql`
- `control_plane/sql/rls.sql`

They create:

- `tenants`
- `users`
- `agents`
- `incidents`
- `usage_metrics`
- `policies`
- `refresh_tokens`
- `audit_logs`

RLS uses:

```sql
current_setting('app.current_tenant_id', true)
```

### Local Run

Start infrastructure:

```powershell
docker compose up -d postgres zookeeper kafka
```

Start the control plane:

```powershell
docker compose up control-plane-api
```

Or run directly:

```powershell
pip install -r requirements.txt
$env:CONTROL_PLANE_DATABASE_URL="postgresql+psycopg2://sentinelai:sentinelai@localhost:5432/sentinelai"
uvicorn control_plane.main:app --host 0.0.0.0 --port 8010
```

### Default Admin

- email: `admin@sentinelai.local`
- password: `ChangeMe123!`

### Agent Enrollment

1. Create an agent via `POST /agents` as a tenant admin.
2. Copy the returned `enrollment_token` into `agent/state/enrollment_token.txt`.
3. Start the agent with:

```powershell
$env:SENTINEL_AGENT_CONTROL_PLANE_URL="http://localhost:8010"
python -m agent.main
```

The agent will:

- enroll against `/agents/enroll`
- receive `agent_id`, `tenant_id`, and Kafka routing info
- send heartbeat data to `/agents/{agent_id}/heartbeat`
- publish tenant-keyed telemetry to Kafka topic `tenant-events`

### Windows Service

Run as a Windows service:

```powershell
python -m agent.windows_service install
python -m agent.windows_service start
```

### Kafka Topic Layout

- `tenant-events`
- `normalized-events`
- `scored-events`
- `alerts`
- `response-actions`
- `dead-letter-queue`

Partition key strategy:

- use `tenant_id` as message key
- preserve per-tenant ordering
- route malformed events to DLQ instead of crashing consumers

### Response Engine

`response_engine/` is safe-mode only by default:

- `isolate_process` simulated
- `block_ip` simulated
- `kill_process` guarded

Every action is audit logged to `storage/response/audit.jsonl`.

### Billing

`billing/` tracks SaaS plan limits and mock subscription flows:

- free
- pro
- enterprise
