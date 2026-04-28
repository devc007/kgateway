# EP-13891: E2E Testing Framework Selection — Adopt Conformance Framework

* Issue: [13891](https://github.com/kgateway-dev/kgateway/issues/13891)
* Parent epic: [Modernize and improve kgateway end-to-end testing](https://github.com/kgateway-dev/kgateway/issues/13783)

---

## Simple Summary

**Problem:** kgateway's custom e2e testing framework is slow, complex to learn, and only used by kgateway.

**Solution:** Move to the **Gateway API conformance framework** — the same framework upstream uses to test Gateway API implementations. Tests are simpler, faster, and designed exactly for what we're testing.

**Benefit:** 
- Tests run 5-10x faster
- Easier to write (less boilerplate)
- Can test both Gateway API compliance AND kgateway features
- Portable (other implementations use it too)

---

## What We're Actually Testing

kgateway does two things:

1. **Implement the Gateway API spec** (HTTPRoute, TLSRoute, Gateway, etc.)
2. **Add kgateway features** (TrafficPolicy, BackendConfigPolicy, ExtAuth, etc.)

The Gateway API project already has a framework for #1: **the conformance framework**. We should use it for both.

### Current Problem (Confusing)

```
test/e2e/                     # Custom framework tests
├─ basicrouting/
├─ cors/
└─ ...

make conformance              # Conformance framework tests
```

Two different frameworks for similar jobs. Confusing and slow.

### Proposed Solution (Clean)

```
gateway-api/conformance/tests/    # Upstream spec tests (unchanged)
kgateway-conformance/             # Our conformance tests
├─ basicrouting/                  # Gateway API compliance for kgateway
├─ cors/                          # (same framework, kgateway additions)
├─ trafficpolicy/                 # kgateway-specific features
├─ backendconfig/                 # (same framework)
└─ ...

make conformance                   # Runs ALL tests (spec + features)
```

One framework. Everything uses it. Clear and fast.

---

## Why the Conformance Framework?

### Speed: 5-10x Faster

**Current custom framework:**
- Per test: wait for images (~5-10s), apply manifests, await pods, run test
- Example basicrouting test: 20-50 seconds setup

**Conformance framework:**
- Per test: apply manifests, run test, cleanup
- Example basicrouting test: 2-5 seconds

**Why the difference:** Conformance framework assumes kgateway is already running. It does NOT:
- Pre-pull images per test (done once at setup)
- Wait for pods in every test (only for new resources)
- Manage Helm installs per test (assumes running cluster)

### Simplicity: Less Boilerplate

**Current framework (basicrouting example):**

```go
// 25+ lines of setup code just to define one test
type testingSuite struct {
    *base.BaseTestingSuite
    localGateway common.Gateway
}

func NewTestingSuite(ctx context.Context, testInst *e2e.TestInstallation) suite.TestingSuite {
    return &testingSuite{
        base.NewBaseTestingSuite(ctx, testInst, setup, testCases),
        common.Gateway{},
    }
}

func (s *testingSuite) SetupSuite() {
    s.BaseTestingSuite.SetupSuite()
    address := s.TestInstallation.Assertions.EventuallyGatewayAddress(s.Ctx, "gateway", "default")
    s.localGateway = common.Gateway{...}
}

func (s *testingSuite) TestGatewayWithRoute() {
    s.assertSuccessfulResponse()  // Finally!
}
```

**Conformance framework (same test):**

```go
// 15 lines total, clear and direct
var BasicRouting = ConformanceTest{
    ShortName: "Basic Routing",
    Features: []features.FeatureName{
        features.SupportGateway,
        features.SupportHTTPRoute,
    },
    Manifests: []string{"basicrouting.yaml"},
    Test: func(t *testing.T, suite *ConformanceTestSuite) {
        gw := &gatewayv1.Gateway{}
        require.NoError(t, suite.Client.Get(ctx, types.NamespacedName{
            Name: "test-gateway", Namespace: "default",
        }, gw))
        
        http.MakeRequestAndExpectEventuallyConsistentResponse(
            t, suite.RoundTripper, suite.TimeoutConfig,
            gw.Status.Addresses[0].Value, expectedResponse,
        )
    },
}

func init() {
    ConformanceTests = append(ConformanceTests, BasicRouting)
}
```

**Key differences:**
- No `BaseTestingSuite`, no `SetupSuite`, no `TestCase` map
- Direct test function
- Use real Gateway API types and helpers

### Designed for This Job

**Conformance framework is built for:** "I am testing an implementation of Gateway API. Here's a manifest, here's what should happen. Verify it works."

**Current custom framework tries to be:** "I need to manage Helm, image pre-pull, version gating, status dumps, AND test features. Let me build a huge kitchen-sink."

kgateway **IS** a Gateway API implementation. The conformance framework is designed exactly for this.

---

## Three Frameworks Compared

| What | Current | sigs/e2e | Conformance |
|------|---------|----------|------------|
| **Test speed** | Slow (heavy setup) | Medium | Fast |
| **Code per test** | 25+ lines setup | 15 lines | 12 lines |
| **Learning curve** | Hard (custom abstractions) | Medium (Go test idioms) | Medium (Gateway API) |
| **HTTP/gRPC/TLS helpers** | Custom (we maintain) | None (bring your own) | Rich (upstream maintains) |
| **Failure dumps** | Yes | No (build it) | No (but we can add) |
| **Feature gating** | Custom version checks | None | Built-in (features) |
| **Who else uses it** | Only kgateway | Crossplane, kueue, others | Kubernetes SIG (official) |
| **Match to kgateway** | Partial (does too much) | Partial (does too little) | **Perfect** |

---

## How to Extend Conformance for kgateway Features

Conformance framework tests **Gateway API spec compliance**. For kgateway-specific features (TrafficPolicy, OAuth2, ExtAuth, etc.), we write **out-of-tree conformance tests** in the repo:

```go
// In kgateway-conformance/ (our own code, not upstream)
var TrafficPolicyWeighted = ConformanceTest{
    ShortName: "TrafficPolicy weighted backends",
    Manifests: []string{"traffic-policy-weighted.yaml"},
    Test: func(t *testing.T, suite *ConformanceTestSuite) {
        // Test your policy behavior
        http.MakeRequestAndExpectEventuallyConsistentResponse(...)
    },
}

func init() {
    ConformanceTests = append(ConformanceTests, TrafficPolicyWeighted)
}
```

**This works because:**
- Conformance framework is extensible (tests are just registered functions)
- We have all the helpers we need (manifest apply, HTTP requests, status checks)
- Tests run in same suite as upstream spec tests
- `make conformance` runs everything together

---

## Real Numbers

### Speed Comparison (estimate)

```
Test                   Current   Conformance   Speedup
─────────────────────────────────────────────────────
basicrouting           30-50s    2-5s          10x
cors                   25-40s    2-4s          10x
header_modifiers       20-35s    2-4s           10x
─────────────────────────────────────────────────────
Suite of 10 tests      3-5 min   20-40s        5-10x
```

**Why:** Conformance doesn't re-do setup per test. Setup happens once.

### Code Comparison

```
Framework              Lines per test    Overhead
─────────────────────────────────────────────────
Current custom         25-50             Lots of setup
sigs/e2e               10-20             Some setup
Conformance            8-15              Minimal setup
```

---

## Implementation Plan

### Phase 1: Foundation (Weeks 1-2)

- [ ] Create `kgateway-conformance/` directory (or `test/conformance-kgateway/`)
- [ ] Set up out-of-tree test registration
- [ ] Port current custom tests as conformance tests (start with basicrouting)
- [ ] Add missing helpers to conformance suite (image pre-pull, failure dumps)
- [ ] Run both frameworks in CI (side-by-side)

### Phase 2: Migrate Core Tests (Weeks 3-6)

- [ ] Migrate basicrouting, cors, header_modifiers to conformance
- [ ] Delete corresponding custom tests
- [ ] Verify test speed and flakiness improvements

### Phase 3: Broaden & Document (Weeks 7-10)

- [ ] Migrate remaining tests
- [ ] Migrate kgateway-specific feature tests (TrafficPolicy, OAuth2, etc.)
- [ ] Write contributor guide: "How to write a conformance test"
- [ ] Update CI/docs

### Phase 4: Retire Custom Framework (Week 11+)

- [ ] When custom framework is empty, archive it
- [ ] Keep `test/e2e/` for utility code only

---

## Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| Conformance framework doesn't support feature X | It's Go code — extend it or patch locally. Not a black box. |
| Tests break during migration | Run both frameworks in parallel for one release cycle. Migrate incrementally. |
| kgateway features can't be tested | They can — out-of-tree conformance tests are first-class. Same framework. |
| Lose rich failure diagnostics | Add failure dump hook to conformance suite (not hard, can PR upstream) |

---

## Why This Is Better for kgateway

1. **We ARE a Gateway API implementation.** This is the framework for testing Gateway API implementations.
2. **Speed matters.** 10x faster tests = faster CI, faster local iteration, happier developers.
3. **Less to maintain.** We use upstream framework, not maintain our own.
4. **Portable.** Other projects use it. Our tests are understandable to them.
5. **Simpler tests.** Less boilerplate, clearer code, easier to debug.

---

## Decision

**Adopt Gateway API conformance framework for all new e2e tests in kgateway.**

- Use it for Gateway API spec tests (already doing via `make conformance`)
- Use it for kgateway feature tests (TrafficPolicy, OAuth2, etc.) — out-of-tree
- Treat current custom framework as legacy; migrate opportunistically
- Invest in extending conformance framework with kgateway-specific helpers (failure dumps, image pre-pull)

This aligns kgateway with the Kubernetes ecosystem and makes testing simpler, faster, and clearer.
