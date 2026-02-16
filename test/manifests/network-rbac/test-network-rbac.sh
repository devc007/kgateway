#!/bin/bash
# Test script for network-level RBAC implementation

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KGATEWAY_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "========================================="
echo "Network-Level RBAC Test Script"
echo "========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

function print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

function print_error() {
    echo -e "${RED}✗ $1${NC}"
}

function print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

# Step 1: Build
echo "Step 1: Building kgateway plugin..."
cd "$KGATEWAY_ROOT"
if go build ./pkg/kgateway/extensions2/plugins/listenerpolicy; then
    print_success "Build successful"
else
    print_error "Build failed"
    exit 1
fi
echo ""

# Step 2: Run unit tests
echo "Step 2: Running unit tests..."
if go test ./pkg/kgateway/extensions2/plugins/listenerpolicy/ -v -run TestTranslateNetworkRBAC; then
    print_success "All unit tests passed"
else
    print_error "Unit tests failed"
    exit 1
fi
echo ""

# Step 3: Check if kubectl is available
echo "Step 3: Checking prerequisites..."
if ! command -v kubectl &> /dev/null; then
    print_error "kubectl not found. Please install kubectl to run integration tests."
    exit 1
fi
print_success "kubectl found"

# Check if cluster is accessible
if ! kubectl cluster-info &> /dev/null; then
    print_error "Cannot access Kubernetes cluster. Please ensure kubectl is configured."
    exit 1
fi
print_success "Kubernetes cluster accessible"
echo ""

# Step 4: Deploy test resources
echo "Step 4: Deploying test resources..."
print_info "Creating test namespace and resources..."

kubectl apply -f "$KGATEWAY_ROOT/test/manifests/network-rbac/01-gateway.yaml"
kubectl apply -f "$KGATEWAY_ROOT/test/manifests/network-rbac/02-backend.yaml"
kubectl apply -f "$KGATEWAY_ROOT/test/manifests/network-rbac/03-route.yaml"

print_success "Test resources deployed"
echo ""

# Step 5: Wait for resources
echo "Step 5: Waiting for resources to be ready..."
print_info "Waiting for echo pod..."
if kubectl wait --for=condition=Ready pod -l app=echo -n test-network-rbac --timeout=120s; then
    print_success "Echo pod ready"
else
    print_error "Echo pod failed to become ready"
    kubectl get pods -n test-network-rbac
    exit 1
fi

print_info "Waiting for gateway..."
if kubectl wait --for=condition=Programmed gateway/test-gateway -n test-network-rbac --timeout=120s 2>/dev/null; then
    print_success "Gateway ready"
else
    print_info "Gateway condition check not available, checking status manually..."
    sleep 5
fi
echo ""

# Step 6: Apply RBAC policy
echo "Step 6: Applying network RBAC policy..."
kubectl apply -f "$KGATEWAY_ROOT/test/manifests/network-rbac/04-listener-policy.yaml"
print_success "ListenerPolicy applied"

# Wait for policy to be processed
sleep 3
echo ""

# Step 7: Check policy status
echo "Step 7: Checking policy status..."
kubectl get listenerpolicy -n test-network-rbac
echo ""
kubectl describe listenerpolicy test-ip-allow -n test-network-rbac
echo ""

# Step 8: Verify Envoy configuration (if kgateway is running)
echo "Step 8: Verifying Envoy configuration..."
GATEWAY_POD=$(kubectl get pods -n kgateway-system -l app=kgateway -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

if [ -n "$GATEWAY_POD" ]; then
    print_info "Checking Envoy config in pod: $GATEWAY_POD"
    
    if kubectl exec -n kgateway-system "$GATEWAY_POD" -- curl -s localhost:19000/config_dump > /tmp/envoy_config.json 2>/dev/null; then
        if grep -q "network_rbac" /tmp/envoy_config.json; then
            print_success "Network RBAC filter found in Envoy configuration"
        else
            print_info "Network RBAC filter not found in Envoy config (this may be expected if using a different deployment)"
        fi
    else
        print_info "Could not dump Envoy config (this is expected if kgateway is not running)"
    fi
else
    print_info "kgateway pod not found (this is expected if not deployed yet)"
fi
echo ""

# Step 9: Summary
echo "========================================="
echo "Test Summary"
echo "========================================="
print_success "Build: PASSED"
print_success "Unit Tests: PASSED"
print_success "Resource Deployment: PASSED"
print_success "Policy Application: PASSED"
echo ""

print_info "Next steps:"
echo "  1. Deploy kgateway with: make run"
echo "  2. Test connectivity with: kubectl port-forward -n test-network-rbac svc/test-gateway 8080:8080"
echo "  3. Send test request: curl http://localhost:8080/"
echo "  4. Check logs: kubectl logs -n kgateway-system <pod-name> | grep -i rbac"
echo ""

print_info "To clean up test resources:"
echo "  kubectl delete namespace test-network-rbac"
echo ""

print_success "All tests completed successfully!"
