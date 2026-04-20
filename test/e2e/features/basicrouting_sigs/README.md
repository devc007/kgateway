# Basic Routing Tests using sigs/e2e-framework

This directory contains a POC for migrating kgateway's end-to-end tests to use the [sigs/e2e-framework](https://github.com/kubernetes-sigs/e2e-framework) from the Kubernetes community.

## Test Structure

- **main_test.go** - Initializes the test environment via TestMain
- **routing_test.go** - Contains the actual test cases
- **assertions/assertions.go** - Centralized assertion helpers
- **testdata/** - Kubernetes manifests used in tests (for reference and documentation)

## What These Tests Validate

The tests validate basic HTTP routing through a kgateway gateway instance:

1. **TestGatewayWithRoute** - Tests that HTTP requests to a gateway are correctly routed to backend services on both high (8080) and low (80) port listeners with individual assessment steps
2. **TestGatewayWithRouteUsingAssertionHelper** - Same validation but using a centralized assertion helper from the assertions package

## Setup Instructions

### Prerequisites

1. A running Kubernetes cluster (e.g., kind, k3s, or real cluster)
2. kgateway controller installed and running
3. The test Gateway and HTTPRoute resources applied to the cluster
4. A backend service (nginx pod) running in the cluster

### Installation Steps

1. **Create the kind cluster** (if not already done):
   ```bash
   make kind-create
   ```

2. **Build and deploy kgateway**:
   ```bash
   make kind-build-and-load
   make deploy-kgateway
   ```

3. **Apply test resources** to the cluster:
   ```bash
   kubectl apply -f test/e2e/features/basicrouting_sigs/testdata/gateway-with-route.yaml
   kubectl apply -f test/e2e/features/basicrouting_sigs/testdata/service.yaml
   ```

4. **Wait for resources to be ready**:
   ```bash
   kubectl wait --for=condition=ready pod/nginx --timeout=60s
   kubectl wait --for=condition=accepted gateway/gateway --timeout=60s
   ```

## Running the Tests

### Run all tests in this suite:

```bash
make e2e-test TEST_PKG=./test/e2e/features/basicrouting_sigs
```

### Run a specific test:

```bash
go test -timeout 30s -run TestGatewayWithRoute ./test/e2e/features/basicrouting_sigs -tags=e2e -kubeconfig=$HOME/.kube/config
```

### Run with custom kubeconfig:

```bash
make e2e-test TEST_PKG=./test/e2e/features/basicrouting_sigs KUBECONFIG=$HOME/.kube/config
```

## Test Resources

The `testdata/` folder contains the Kubernetes manifests needed to run these tests:

- **gateway-with-route.yaml** - Defines a Gateway with two listeners (ports 80 and 8080) and an HTTPRoute that routes example.com to the backend service
- **service.yaml** - Defines a Service and Pod (nginx) that acts as the backend

These resources must be present in the cluster before running the tests. They are not created/destroyed by the tests themselves - the tests assume they are already installed.

## Architecture

### Key Components

1. **sigs/e2e-framework** - Provides test lifecycle management (Setup, Assess, Teardown)
2. **features.New()** - Creates a named test feature
3. **.Setup()** - Runs once before assessments to initialize state (e.g., get gateway address)
4. **.Assess()** - Individual test step that validates behavior
5. **common.Gateway.Send()** - Helper method that sends HTTP requests and validates responses with retries
6. **assertions package** - Reusable assertion helpers to avoid duplication

### Flow

1. TestMain initializes the sigs/e2e-framework environment from kubeconfig
2. Each test feature:
   - Runs Setup to fetch the gateway address from the cluster
   - Stores the gateway in context for use by assessments
   - Runs multiple Assess steps (each testing specific ports/scenarios)
   - Implicitly cleans up context when done

## Comparison with Previous Framework

### Previous Approach (testify/suite)
- Used Ginkgo-like test structure with suite methods
- Required custom kgateway framework (BaseTestingSuite)
- Manifest application managed by suite infrastructure
- Shared state via struct fields

### New Approach (sigs/e2e-framework)
- Uses declarative feature-based structure
- Standard Kubernetes test framework
- Resources assumed to be pre-installed
- Shared state via context.Context
- Each test is self-contained and easier to understand

## Benefits of This Approach

✅ Uses standard Kubernetes testing patterns  
✅ Better separation of concerns (assertions in own package)  
✅ Self-documenting test structure via features.New()  
✅ Reusable assertion helpers  
✅ Clearer resource management  
✅ Easier to debug individual test steps  

## Debugging

To debug a specific test:

```bash
go test -timeout 60s -run TestGatewayWithRoute -v ./test/e2e/features/basicrouting_sigs -tags=e2e -kubeconfig=$HOME/.kube/config
```

Check gateway address:
```bash
kubectl get gateway gateway -o jsonpath='{.status.addresses[0].value}'
```

Verify backend is running:
```bash
kubectl get pod nginx
kubectl logs nginx
```

## Future Work

This POC demonstrates how to:
- Migrate existing tests to sigs/e2e-framework
- Organize assertions into reusable packages
- Document test resources separately
- Provide clear setup/run instructions

Other tests in the suite can follow the same pattern for consistency.
