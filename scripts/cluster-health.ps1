param(
    [string]$Namespace = "sentinelai-prod"
)

kubectl get pods -n $Namespace
kubectl get svc -n $Namespace
kubectl get ingress -n $Namespace
kubectl top pods -n $Namespace
