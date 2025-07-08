package downward_test

import (
	envoy_config_bootstrap "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/protobuf/types/known/structpb"

	. "github.com/kgateway-dev/kgateway/v2/internal/envoyinit/pkg/downward"
)

var _ = Describe("Transform", func() {

	Context("bootstrap transforms", func() {
		var (
			api             *mockDownward
			bootstrapConfig *envoy_config_bootstrap.Bootstrap
		)
		BeforeEach(func() {
			api = &mockDownward{
				podName: "Test",
				nodeIp:  "5.5.5.5",
			}
			bootstrapConfig = new(envoy_config_bootstrap.Bootstrap)
			bootstrapConfig.Node = &corev3.Node{}
		})

		It("should transform node id", func() {

			bootstrapConfig.Node.Id = "{{.PodName}}"
			err := TransformConfigTemplatesWithApi(bootstrapConfig, api)
			Expect(err).NotTo(HaveOccurred())
			Expect(bootstrapConfig.Node.Id).To(Equal("Test"))
		})

		It("should transform cluster", func() {
			bootstrapConfig.Node.Cluster = "{{.PodName}}"
			err := TransformConfigTemplatesWithApi(bootstrapConfig, api)
			Expect(err).NotTo(HaveOccurred())
			Expect(bootstrapConfig.Node.Cluster).To(Equal("Test"))
		})

		It("should transform metadata", func() {
			bootstrapConfig.Node.Metadata = &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"foo": {
						Kind: &structpb.Value_StringValue{
							StringValue: "{{.PodName}}",
						},
					},
				},
			}

			err := TransformConfigTemplatesWithApi(bootstrapConfig, api)
			Expect(err).NotTo(HaveOccurred())
			Expect(bootstrapConfig.Node.Metadata.Fields["foo"].Kind.(*structpb.Value_StringValue).StringValue).To(Equal("Test"))
		})

		It("should transform static resources", func() {
			bootstrapConfig.StaticResources = &envoy_config_bootstrap.Bootstrap_StaticResources{
				Clusters: []*clusterv3.Cluster{{
					LoadAssignment: &envoy_config_endpoint_v3.ClusterLoadAssignment{
						Endpoints: []*envoy_config_endpoint_v3.LocalityLbEndpoints{{
							LbEndpoints: []*envoy_config_endpoint_v3.LbEndpoint{{
								HostIdentifier: &envoy_config_endpoint_v3.LbEndpoint_Endpoint{
									Endpoint: &envoy_config_endpoint_v3.Endpoint{
										Address: &corev3.Address{
											Address: &corev3.Address_SocketAddress{
												SocketAddress: &corev3.SocketAddress{
													Address: "{{.NodeIp}}",
												},
											},
										},
									},
								},
							}},
						}},
					},
				}},
			}

			err := TransformConfigTemplatesWithApi(bootstrapConfig, api)
			Expect(err).NotTo(HaveOccurred())

			expectedAddress := bootstrapConfig.GetStaticResources().GetClusters()[0].GetLoadAssignment().GetEndpoints()[0].GetLbEndpoints()[0].GetEndpoint().GetAddress().GetSocketAddress().GetAddress()
			Expect(expectedAddress).To(Equal("5.5.5.5"))
		})

	})
})
