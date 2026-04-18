param(
    [string]$Namespace = "sentinelai-prod"
)

$ErrorActionPreference = "Stop"

istioctl install -y
kubectl label namespace $Namespace istio-injection=enabled --overwrite
kubectl apply -f service_mesh\istio\peer-authentication.yaml
kubectl apply -f service_mesh\istio\destination-rules.yaml
kubectl apply -f service_mesh\istio\virtual-services.yaml
