//go:build e2e

package assertions

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	listenerHighPort = 8080
	listenerLowPort  = 80

	// echoResponseMarker is a substring the gateway-api echo-basic server
	// includes in every response body (it echoes back the pod name in JSON).
	echoResponseMarker = "basicrouting-echo"
)

// AssertSuccessfulResponse validates that the gateway address responds with HTTP 200
// and the echo response body on both the high port (8080) and low port (80) listeners.
func AssertSuccessfulResponse(t *testing.T, gatewayAddress string) {
	t.Helper()
	for _, port := range []int{listenerHighPort, listenerLowPort} {
		assertHTTPResponse(t, gatewayAddress, port)
	}
}

// assertHTTPResponse sends an HTTP request to the gateway on the given port
// and validates a 200 response. Retries for up to 30s.
func assertHTTPResponse(t *testing.T, address string, port int) {
	t.Helper()

	url := fmt.Sprintf("http://%s:%d", address, port)
	deadline := time.Now().Add(30 * time.Second)

	var lastErr error
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			t.Fatalf("failed to build request: %v", err)
		}
		req.Host = "example.com"

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(1 * time.Second)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			time.Sleep(1 * time.Second)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("port %d: expected status 200, got %d", port, resp.StatusCode)
			time.Sleep(1 * time.Second)
			continue
		}

		if !strings.Contains(string(body), echoResponseMarker) {
			lastErr = fmt.Errorf("port %d: body does not contain %q", port, echoResponseMarker)
			time.Sleep(1 * time.Second)
			continue
		}

		return // success
	}

	t.Errorf("port %d: assertion failed after 30s: %v", port, lastErr)
}
