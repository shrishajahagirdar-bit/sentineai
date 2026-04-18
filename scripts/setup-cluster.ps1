param(
    [string]$Namespace = "sentinelai-prod",
    [string]$ClusterName = "sentinelai-local",
    [ValidateSet("kind", "minikube")]
    [string]$Provider = "kind"
)

$ErrorActionPreference = "Stop"

if ($Provider -eq "kind") {
    kind create cluster --name $ClusterName
}
else {
    minikube start --profile $ClusterName
}

kubectl apply -f k8s\namespaces.yaml
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update
helm upgrade --install sentinelai-kafka bitnami/kafka --namespace $Namespace --set kraft.enabled=false --set zookeeper.enabled=true
helm upgrade --install sentinelai-postgresql bitnami/postgresql --namespace $Namespace --set auth.username=sentinelai --set auth.password=sentinelai --set auth.database=sentinelai
helm upgrade --install sentinelai .\helm\sentinelai --namespace $Namespace
kubectl rollout status deployment/control-plane-api -n $Namespace
kubectl rollout status deployment/ml-inference -n $Namespace
kubectl rollout status deployment/stream-processor -n $Namespace
kubectl rollout status deployment/dashboard-frontend -n $Namespace
