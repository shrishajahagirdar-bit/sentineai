param(
    [string]$Namespace = "sentinelai-prod"
)

Start-Process powershell -ArgumentList "-NoExit", "-Command", "kubectl port-forward svc/control-plane-api 8010:8010 -n $Namespace"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "kubectl port-forward svc/dashboard-frontend 8501:8501 -n $Namespace"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "kubectl port-forward svc/ml-inference 8030:8030 -n $Namespace"
