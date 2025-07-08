package pluginutils

import (
	"fmt"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/utils"
)

func EnvoySingleEndpointLoadAssignment(out *clusterv3.Cluster, address string, port uint32) {
	out.LoadAssignment = &envoy_config_endpoint_v3.ClusterLoadAssignment{
		ClusterName: out.GetName(),
		Endpoints: []*envoy_config_endpoint_v3.LocalityLbEndpoints{
			{
				LbEndpoints: []*envoy_config_endpoint_v3.LbEndpoint{
					{
						HostIdentifier: &envoy_config_endpoint_v3.LbEndpoint_Endpoint{
							Endpoint: EnvoyEndpoint(address, port),
						},
					},
				},
			},
		},
	}
}

func EnvoyEndpoint(address string, port uint32) *envoy_config_endpoint_v3.Endpoint {
	return &envoy_config_endpoint_v3.Endpoint{
		Address: &corev3.Address{
			Address: &corev3.Address_SocketAddress{
				SocketAddress: &corev3.SocketAddress{
					Address: address,
					PortSpecifier: &corev3.SocketAddress_PortValue{
						PortValue: port,
					},
				},
			},
		},
	}
}

func SetExtensionProtocolOptions(out *clusterv3.Cluster, filterName string, protoext proto.Message) error {
	protoextAny, err := utils.MessageToAny(protoext)
	if err != nil {
		return fmt.Errorf("converting extension %s protocol options to struct: %w", filterName, err)
	}
	if out.GetTypedExtensionProtocolOptions() == nil {
		out.TypedExtensionProtocolOptions = make(map[string]*anypb.Any)
	}

	out.GetTypedExtensionProtocolOptions()[filterName] = protoextAny
	return nil
}
