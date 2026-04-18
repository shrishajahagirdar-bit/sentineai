# SentinelAI Streaming SOC Platform

## Architecture Diagram

```text
                    +----------------------+
                    |  Tenant Users / APIs |
                    +----------+-----------+
                               |
                               v
 +----------------+   +--------+--------+   +----------------------+
 | Log Collectors |-->| Kafka / Stream  |-->| Stream Processor     |
 | Attack Sim     |   | Topic: security |   | feature extraction   |
 +----------------+   | logs            |   | UEBA + online ML     |
                      +--------+--------+   | drift + scoring       |
                               |            +-----+----------------+
                               |                  |
                               v                  v
                    +----------+--------+   +-----+----------------+
                    | FastAPI Gateway   |   | Postgres / Event     |
                    | JWT + tenant      |   | storage / audit logs |
                    | routing + RBAC    |   +-----+----------------+
                    +----------+--------+         |
                               |                  |
                               v                  v
                    +----------+------------------+------+
                    | Dashboard / Investigation / Alerts |
                    +------------------------------------+
```

## Component Breakdown

- Multi-tenant layer: tenant-aware API gateway, JWT auth, RBAC roles `admin`, `analyst`, `viewer`, tenant-routed storage.
- Streaming layer: producer emits telemetry and simulated attacks into `security-logs`; consumer groups scale horizontally.
- Intelligence layer: stream processor performs schema validation, feature extraction, UEBA enrichment, online SGD updates, drift detection, and risk scoring.
- Storage layer: PostgreSQL for tenants, alerts, audit logs; object/time-series storage for raw events and replay.
- UI layer: Streamlit or React SOC dashboard with live alerts, timelines, and investigations.
- Security layer: row-level tenant isolation, audit trails, alert triage controls, model rollback on drift.

## Data Flow

1. Telemetry, collector output, and simulated attack events are published to `security-logs`.
2. Consumer instances pull events by consumer group and validate against the canonical schema.
3. Dict-only stream feature extraction computes login frequency, IP change rate, request rate, severity score, and time context.
4. Online ML scores the event and performs `partial_fit` updates when labels are available.
5. Drift detection compares recent error against a stable baseline and reverts to the last good model if needed.
6. Scoring engine combines ML, UEBA, severity, and attack weights into a 0-100 risk score.
7. Alert generator emits analyst-facing alerts and persists incidents for dashboard and API access.

## Scaling Strategy

- `1K events/sec`: single Kafka topic, 3 consumer replicas, online model in-memory per worker, Postgres primary + read replica.
- `10K events/sec`: partition `security-logs` by tenant or source, autoscale consumers, push cold raw logs to object storage.
- `100K events/sec`: dedicated Kafka cluster, per-tenant partitions, stateless stream workers, Redis feature cache, ClickHouse/OpenSearch for hot investigations.

## 48-Hour Plan

### First 24 Hours

- Stand up Kafka-compatible ingestion and stream processor.
- Enable online learning, drift rollback, and scoring engine.
- Expose alerts and incidents through FastAPI.
- Connect dashboard to live alert feed.

### Next 24 Hours

- Add tenant-aware auth and tenant routing middleware.
- Move incidents, alerts, and audit logs to PostgreSQL.
- Add CI/CD, container build, and environment configs.
- Ship investor demo with attack replay and real-time alert narrative.

## Market Positioning

- SentinelAI is a cloud-native Splunk and Microsoft Sentinel alternative for modern SOC teams.
- Kafka plus online ML is defensible because detection quality improves continuously with live tenant behavior.
- Enterprise readiness comes from tenant isolation, auditability, model rollback, and scalable stream processing.

## Pricing Model

- Free: single tenant, capped event volume, community support.
- Pro: higher daily event volume, UEBA, alert workflows, API access.
- Enterprise: dedicated partitions, SSO, custom retention, advanced compliance, premium support.

## Deployment

- Preferred cloud: AWS with MSK, EKS, RDS Postgres, S3, and CloudWatch.
- GCP alternative: GKE, Pub/Sub or Kafka, Cloud SQL, GCS.
- CI/CD: GitHub Actions -> tests -> container build -> deploy to Kubernetes -> smoke tests.
- Monitoring: Prometheus, Grafana, Loki, OpenTelemetry, and alerting on consumer lag and model drift.
