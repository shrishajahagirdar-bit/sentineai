## SentinelAI Cloud-Native Architecture

### Deployment Plan

SentinelAI is deployed as a multi-service Kubernetes platform with three planes:

```text
Data Plane
- windows/linux agents
- kafka
- stream processor
- ml inference
- response engine

Control Plane
- control-plane-api
- agent-manager
- tenant auth / billing / policy APIs

Observability Plane
- Prometheus
- Grafana
- Fluent Bit
- OpenSearch
- Kibana
- OpenTelemetry Collector
```

### Helm Layout

```text
helm/sentinelai/
  Chart.yaml
  values.yaml
  templates/
    deployment.yaml
    service.yaml
    ingress.yaml
    hpa.yaml
    configmap.yaml
    secrets.yaml
    postgresql-statefulset.yaml
    kafka-statefulset.yaml
    networkpolicy.yaml
```

### Namespaces

- `sentinelai-dev`
- `sentinelai-prod`

### Multi-Tenant Routing

Gateway ingress routes:

- `/tenant/control-plane` -> control plane
- `/tenant/agents` -> agent manager
- `/` -> dashboard

### Kafka and PostgreSQL

- Kafka and Zookeeper are deployed as StatefulSets with persistent volumes.
- PostgreSQL is deployed as a StatefulSet with persistent storage and internal DNS discovery.

### Security

- deny-by-default network policies
- Vault-backed secret bootstrap
- service mesh / mTLS sidecar model
- tenant-aware ingress and API routing
