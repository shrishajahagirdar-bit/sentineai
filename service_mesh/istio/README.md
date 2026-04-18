Apply Istio first, then these SentinelAI policies:

1. `kubectl apply -f service_mesh/istio/peer-authentication.yaml`
2. `kubectl apply -f service_mesh/istio/destination-rules.yaml`
3. `kubectl apply -f service_mesh/istio/virtual-services.yaml`
4. `kubectl apply -f service_mesh/istio/canary-deployments.yaml`

This enables strict mTLS, mesh retries/timeouts, outlier detection, and canary routing for the control plane and ML service.
