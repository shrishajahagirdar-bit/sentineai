## SentinelAI Zero-Trust Security Architecture

### mTLS

SentinelAI assumes mTLS for:

- agent -> control plane
- service -> service
- Kafka clients -> brokers

Implementation model:

- certificates issued per service identity
- agent certificates scoped to tenant and agent identity
- Kafka broker TLS secrets mounted through Vault or CSI

### Vault

Vault stores and rotates:

- PostgreSQL credentials
- Kafka credentials
- JWT signing keys
- mTLS private keys / certificates

### Cluster Security

- deny-by-default `NetworkPolicy`
- namespace isolation
- least-privilege Kubernetes RBAC
- no static secrets committed to manifests for production
