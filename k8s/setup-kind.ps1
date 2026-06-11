# Ensure kind is on PATH
$env:PATH = "$env:USERPROFILE\.local\bin;$env:PATH"

# Clean up any existing cluster
kind delete cluster --name aegisops 2>&1 | Out-Null

# Create the Kind cluster
Write-Output "=== Creating Kind cluster ==="
kind create cluster --name aegisops --wait 120s

# Verify cluster is running
Write-Output "`n=== Kind clusters ==="
kind get clusters

Write-Output "`n=== Docker containers ==="
docker ps --filter "name=aegisops"

# Export kubeconfig to default location
Write-Output "`n=== Exporting kubeconfig ==="
kind export kubeconfig --name aegisops

# Also export to project-local kubeconfig for kubernetes-asyncio
kind get kubeconfig --name aegisops > "$PSScriptRoot\..\kubeconfig.yaml"
Write-Output "Local kubeconfig written to k8s\..\kubeconfig.yaml"

# Verify kubectl works
Write-Output "`n=== Cluster Info ==="
kubectl cluster-info --context kind-aegisops

# Deploy the payment-service mock workload
Write-Output "`n=== Deploying payment-service ==="
kubectl apply -f "$PSScriptRoot\mock-workloads\payment-service.yaml" --context kind-aegisops

# Wait for deployment to roll out
Write-Output "`n=== Waiting for rollout ==="
kubectl rollout status deployment/payment-service --context kind-aegisops --timeout=120s

Write-Output "`n=== Pods ==="
kubectl get pods --context kind-aegisops

Write-Output "`n=== DONE ==="
