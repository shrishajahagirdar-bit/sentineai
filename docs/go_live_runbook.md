# SentinelAI Go-Live Runbook

## Bootstrap the cluster

```powershell
.\scripts\setup-cluster.ps1
```

## Enable service mesh

```powershell
.\scripts\enable-istio.ps1
```

## Open local access paths

```powershell
.\scripts\port-forward.ps1
```

## Validate the data path

```powershell
python scripts\validate_e2e.py
```

Expected flow:

```text
Agent -> tenant-events -> stream-processor -> ml-inference -> control-plane -> dashboard
```

## Check health

- `.\scripts\cluster-health.ps1`
- `kubectl logs -n sentinelai-prod deployment/control-plane-api`
- `kubectl logs -n sentinelai-prod deployment/stream-processor`

## Failure drills

```powershell
python scripts\failure_injection.py
```
