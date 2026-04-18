param(
    [string]$Namespace = "sentinelai-prod",
    [string]$App = "control-plane-api"
)

kubectl logs -n $Namespace deployment/$App --tail=200 -f
