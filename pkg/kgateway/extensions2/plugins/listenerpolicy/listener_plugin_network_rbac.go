package listenerpolicy

import (
	envoylistenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/types/known/anypb"
)

// Network RBAC filters must be added as network filters, before the HttpConnectionManager.
// This allows connection-level authorization before any HTTP processing occurs.
func (p *listenerPolicyPluginGwPass) applyNetworkRBAC(
	out *envoylistenerv3.Listener,
	networkRBACFilter *anypb.Any,
) {
	if networkRBACFilter == nil {
		return
	}

	// Network RBAC filter must be added to each filter chain
	for _, filterChain := range out.GetFilterChains() {
		// Check if RBAC network filter already exists
		hasRBACFilter := false
		for _, filter := range filterChain.GetFilters() {
			if filter.Name == wellknown.RoleBasedAccessControl {
				logger.Warn("network RBAC filter already exists in filter chain, skipping",
					"listener", out.Name)
				hasRBACFilter = true
				break
			}
		}

		if hasRBACFilter {
			continue
		}

		// Create the network filter
		rbacNetworkFilter := &envoylistenerv3.Filter{
			Name: wellknown.RoleBasedAccessControl,
			ConfigType: &envoylistenerv3.Filter_TypedConfig{
				TypedConfig: networkRBACFilter,
			},
		}

		// Insert the RBAC filter at the beginning of the network filters
		// This ensures it runs before the HttpConnectionManager
		// Network filters are evaluated in order, so RBAC needs to be first
		filterChain.Filters = append([]*envoylistenerv3.Filter{rbacNetworkFilter}, filterChain.GetFilters()...)

		logger.Debug("added network RBAC filter to filter chain",
			"listener", out.Name,
			"filter_chain", filterChain.Name)
	}

	logger.Debug("applied network RBAC filter to listener", "listener", out.Name)
}
