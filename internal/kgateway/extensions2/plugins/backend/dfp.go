package backend

import (
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_dfp_cluster "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/dynamic_forward_proxy/v3"
	envoydfp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/dynamic_forward_proxy/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"

	eiutils "github.com/kgateway-dev/kgateway/v2/internal/envoyinit/pkg/utils"

	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"

	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/utils"
)

var dfpFilterConfig = &envoydfp.FilterConfig{
	ImplementationSpecifier: &envoydfp.FilterConfig_SubClusterConfig{
		SubClusterConfig: &envoydfp.SubClusterConfig{},
	},
}

func processDynamicForwardProxy(in *v1alpha1.DynamicForwardProxyBackend, out *clusterv3.Cluster) error {
	out.LbPolicy = clusterv3.Cluster_CLUSTER_PROVIDED
	c := &envoy_dfp_cluster.ClusterConfig{
		ClusterImplementationSpecifier: &envoy_dfp_cluster.ClusterConfig_SubClustersConfig{
			SubClustersConfig: &envoy_dfp_cluster.SubClustersConfig{
				LbPolicy: clusterv3.Cluster_LEAST_REQUEST,
			},
		},
	}
	anyCluster, err := utils.MessageToAny(c)
	if err != nil {
		return err
	}
	out.ClusterDiscoveryType = &clusterv3.Cluster_ClusterType{
		ClusterType: &clusterv3.Cluster_CustomClusterType{
			Name:        "envoy.clusters.dynamic_forward_proxy",
			TypedConfig: anyCluster,
		},
	}

	if in.EnableTls {
		validationContext := &tlsv3.CertificateValidationContext{}
		sdsValidationCtx := &tlsv3.SdsSecretConfig{
			Name: eiutils.SystemCaSecretName,
		}

		tlsContextDefault := &tlsv3.UpstreamTlsContext{
			CommonTlsContext: &tlsv3.CommonTlsContext{
				ValidationContextType: &tlsv3.CommonTlsContext_CombinedValidationContext{
					CombinedValidationContext: &tlsv3.CommonTlsContext_CombinedCertificateValidationContext{
						DefaultValidationContext:         validationContext,
						ValidationContextSdsSecretConfig: sdsValidationCtx,
					},
				},
			},
		}

		typedConfig, _ := utils.MessageToAny(tlsContextDefault)
		out.TransportSocket = &corev3.TransportSocket{
			Name: wellknown.TransportSocketTls,
			ConfigType: &corev3.TransportSocket_TypedConfig{
				TypedConfig: typedConfig,
			},
		}
	}

	return nil
}
