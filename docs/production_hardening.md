## SentinelAI Production Hardening

### Updated Architecture

```text
Data Plane
- agent telemetry
- kafka topics
- stream processing
- ML + UEBA + risk scoring

Control Plane
- tenant auth / RBAC
- fleet management
- policies
- incidents
- billing

Observability Plane
- structured JSON logs
- correlation IDs
- Prometheus metrics
- tracing hooks
- operational health snapshots
```

### Failure Flow

```text
Agent -> Kafka failure -> local spool fallback -> retry publish
Agent -> Control plane failure -> telemetry continues, degraded mode
Kafka consumer failure -> retry + DLQ
ML failure -> heuristic / rules-first fallback
DB/control plane issues -> request failure isolated, audit + health metrics
```

### Production Readiness Checklist

Complete:
- structured JSON logging
- correlation ID propagation hooks
- Prometheus metrics endpoint on control plane
- Kafka DLQ routing
- retry wrappers
- circuit breaker primitives
- agent spool fallback
- dashboard operational health panel

Partial:
- OpenTelemetry tracing hooks are present but exporter/backends still need environment configuration
- exactly-once semantics are simulated with idempotency and safe retries, not broker transactions
- mTLS and centralized secret management need deployment-time certificate/secret backends

Missing:
- enterprise secret manager integration (Vault/KMS)
- full distributed trace export pipeline
- chaos automation in CI/CD
- persistent lag monitor service across all topics
- formal SLO/error-budget automation
