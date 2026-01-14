// Package discovery provides OAuth 2.0 Authorization Server Metadata discovery
// as defined in RFC 8414 (https://www.rfc-editor.org/rfc/rfc8414).
package discovery

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/avast/retry-go/v4"

	"github.com/kgateway-dev/kgateway/v2/pkg/logging"
)

var logger = logging.New("oauth_discovery")

const (
	// wellKnownOAuthAuthorizationServerPath is the well-known path for OAuth 2.0 Authorization Server Metadata
	// as defined in RFC 8414.
	wellKnownOAuthAuthorizationServerPath = "/.well-known/oauth-authorization-server"

	// wellKnownOpenIDConfigurationPath is the well-known path for OpenID Connect Discovery
	// as a fallback when OAuth metadata is not available.
	wellKnownOpenIDConfigurationPath = "/.well-known/openid-configuration"

	userAgent           = "kgateway/oauth-discovery"
	acceptedContentType = "application/json"
)

// OAuthServerMetadata represents the OAuth 2.0 Authorization Server Metadata response
// as defined in RFC 8414 Section 2. We only parse the fields needed for JWKS discovery.
type OAuthServerMetadata struct {
	// Issuer is the authorization server's issuer identifier
	Issuer string `json:"issuer"`

	// JwksURI is the URL of the authorization server's JWK Set document
	JwksURI string `json:"jwks_uri,omitempty"`
}

// OAuthDiscoverer discovers OAuth 2.0 Authorization Server metadata from well-known endpoints.
type OAuthDiscoverer struct {
	cache                sync.Map
	cacheRefreshInterval time.Duration
	httpClient           *http.Client
}

// cachedMetadata stores metadata with expiration info
type cachedMetadata struct {
	metadata  *OAuthServerMetadata
	fetchedAt time.Time
}

// NewOAuthDiscoverer creates a new OAuthDiscoverer instance.
func NewOAuthDiscoverer() *OAuthDiscoverer {
	return &OAuthDiscoverer{
		cacheRefreshInterval: 5 * time.Minute,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// NewOAuthDiscovererWithTLS creates a new OAuthDiscoverer instance with custom TLS configuration.
func NewOAuthDiscovererWithTLS(tlsConfig *tls.Config) *OAuthDiscoverer {
	return &OAuthDiscoverer{
		cacheRefreshInterval: 5 * time.Minute,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
	}
}

// GetJwksURI discovers and returns the JWKS URI from the OAuth 2.0 Authorization Server Metadata.
// It first tries the OAuth 2.0 well-known endpoint, then falls back to OpenID Connect discovery.
func (d *OAuthDiscoverer) GetJwksURI(issuerURI string) (string, error) {
	metadata, err := d.GetMetadata(issuerURI)
	if err != nil {
		return "", err
	}

	if metadata.JwksURI == "" {
		return "", fmt.Errorf("jwks_uri not found in OAuth server metadata for issuer %s", issuerURI)
	}

	return metadata.JwksURI, nil
}

// GetMetadata retrieves the OAuth 2.0 Authorization Server Metadata for the given issuer.
// Results are cached for performance.
func (d *OAuthDiscoverer) GetMetadata(issuerURI string) (*OAuthServerMetadata, error) {
	// Check cache first
	if cached, ok := d.cache.Load(issuerURI); ok {
		cm := cached.(*cachedMetadata)
		// Return cached value if not expired
		if time.Since(cm.fetchedAt) < d.cacheRefreshInterval {
			return cm.metadata, nil
		}
	}

	// Discover configuration
	metadata, err := d.discover(issuerURI)
	if err != nil {
		return nil, err
	}

	// Cache the configuration
	d.cache.Store(issuerURI, &cachedMetadata{
		metadata:  metadata,
		fetchedAt: time.Now(),
	})

	return metadata, nil
}

// discover fetches OAuth 2.0 Authorization Server Metadata from the well-known endpoints.
// It tries the OAuth 2.0 endpoint first, then falls back to OpenID Connect discovery.
func (d *OAuthDiscoverer) discover(issuerURI string) (*OAuthServerMetadata, error) {
	// Try OAuth 2.0 Authorization Server Metadata endpoint first (RFC 8414)
	metadata, err := d.fetchMetadata(issuerURI, wellKnownOAuthAuthorizationServerPath)
	if err == nil {
		logger.Debug("discovered OAuth server metadata", "issuer", issuerURI, "jwks_uri", metadata.JwksURI)
		return metadata, nil
	}
	logger.Debug("OAuth 2.0 metadata endpoint failed, trying OpenID Connect discovery", "issuer", issuerURI, "error", err)

	// Fall back to OpenID Connect Discovery
	metadata, err = d.fetchMetadata(issuerURI, wellKnownOpenIDConfigurationPath)
	if err == nil {
		logger.Debug("discovered OpenID Connect configuration", "issuer", issuerURI, "jwks_uri", metadata.JwksURI)
		return metadata, nil
	}

	return nil, fmt.Errorf("failed to discover OAuth server metadata for issuer %s: %w", issuerURI, err)
}

// fetchMetadata retrieves metadata from a specific well-known path.
func (d *OAuthDiscoverer) fetchMetadata(issuerURI, wellKnownPath string) (*OAuthServerMetadata, error) {
	// Construct the discovery URL
	discoveryURL, err := url.Parse(issuerURI + wellKnownPath)
	if err != nil {
		return nil, fmt.Errorf("error parsing discovery URL: %w", err)
	}

	metadata := &OAuthServerMetadata{}
	err = retry.Do(func() error {
		req, err := http.NewRequest(http.MethodGet, discoveryURL.String(), nil)
		if err != nil {
			return retry.Unrecoverable(fmt.Errorf("failed to create request: %w", err))
		}

		req.Header.Set("Accept", acceptedContentType)
		req.Header.Set("User-Agent", userAgent)

		resp, err := d.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to fetch metadata: %w", err)
		}
		defer resp.Body.Close()

		switch resp.StatusCode {
		// Retry on specific 5xx status codes
		case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return fmt.Errorf("server error: status code %d", resp.StatusCode)

		case http.StatusOK:
			if err := json.NewDecoder(resp.Body).Decode(metadata); err != nil {
				return retry.Unrecoverable(fmt.Errorf("error decoding metadata: %w", err))
			}

		case http.StatusNotFound:
			return retry.Unrecoverable(fmt.Errorf("metadata endpoint not found: %s", discoveryURL.String()))

		default:
			return retry.Unrecoverable(fmt.Errorf("unexpected status code %d", resp.StatusCode))
		}
		return nil
	}, retry.Attempts(3), retry.Delay(100*time.Millisecond), retry.MaxDelay(2*time.Second), retry.DelayType(retry.BackOffDelay))

	if err != nil {
		return nil, err
	}

	return metadata, nil
}

// Global discoverer instance for convenience
var defaultDiscoverer = NewOAuthDiscoverer()

// DiscoverJwksURI is a convenience function that uses the default discoverer.
func DiscoverJwksURI(issuerURI string) (string, error) {
	return defaultDiscoverer.GetJwksURI(issuerURI)
}
