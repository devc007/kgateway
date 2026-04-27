//go:build e2e

package basicrouting

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	clientset "k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
	confconfig "sigs.k8s.io/gateway-api/conformance/utils/config"
	confsuite "sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"

	"github.com/kgateway-dev/kgateway/v2/pkg/schemes"
)

//go:embed testdata
var manifestFS embed.FS

const (
	gatewayClassName = "kgateway"
	testNamespace    = "kgateway-conformance-test"
	gatewayName      = "conformance-gateway"
	routeName        = "basicrouting-route"
)

// suite holds the conformance test suite shared by all tests in the package.
var suite *confsuite.ConformanceTestSuite

// TestMain wires up a Gateway API conformance ConformanceTestSuite. Individual
// manifests applied through suite.Applier register t.Cleanup hooks, so tests do
// not need to manage manifest teardown explicitly.
func TestMain(m *testing.M) {
	if err := setup(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to set up conformance suite: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func setup() error {
	cfg, err := ctrlconfig.GetConfig()
	if err != nil {
		return fmt.Errorf("loading kubeconfig: %w", err)
	}

	scheme := schemes.GatewayScheme()
	if err := apiextensionsv1.AddToScheme(scheme); err != nil {
		return fmt.Errorf("registering apiextensions scheme: %w", err)
	}

	clientOpts := client.Options{Scheme: scheme}
	cl, err := client.New(cfg, clientOpts)
	if err != nil {
		return fmt.Errorf("creating controller-runtime client: %w", err)
	}
	cs, err := clientset.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("creating clientset: %w", err)
	}

	supported := confsuite.FeaturesSet{}
	supported.Insert(features.SupportGateway, features.SupportHTTPRoute)

	opts := confsuite.ConformanceOptions{
		Client:               cl,
		ClientOptions:        clientOpts,
		Clientset:            cs,
		RestConfig:           cfg,
		GatewayClassName:     gatewayClassName,
		ManifestFS:           []fs.FS{manifestFS},
		CleanupBaseResources: true,
		SupportedFeatures:    supported,
		TimeoutConfig:        confconfig.DefaultTimeoutConfig(),
		AllowCRDsMismatch:    true,
	}

	suite, err = confsuite.NewConformanceTestSuite(opts)
	if err != nil {
		return fmt.Errorf("constructing conformance suite: %w", err)
	}
	// The conformance Applier rewrites every Gateway's spec.gatewayClassName to
	// Applier.GatewayClass at apply time. suite.Setup would normally populate it,
	// but we skip Setup (its TLS bootstrap is unrelated to this POC), so set it
	// here explicitly.
	suite.Applier.ManifestFS = opts.ManifestFS
	suite.Applier.GatewayClass = gatewayClassName
	return nil
}

// applyBaseManifests applies the namespace, gateway, and backend manifests with
// auto-cleanup registered via t.Cleanup.
func applyBaseManifests(t *testing.T) {
	t.Helper()
	suite.Applier.MustApplyWithCleanup(t, suite.Client, suite.TimeoutConfig, "testdata/gateway.yaml", true)
	suite.Applier.MustApplyWithCleanup(t, suite.Client, suite.TimeoutConfig, "testdata/backend.yaml", true)
}
