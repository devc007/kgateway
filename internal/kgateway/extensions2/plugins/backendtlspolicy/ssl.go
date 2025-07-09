package backendtlspolicy

import (
	"errors"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	corev1 "k8s.io/api/core/v1"
)

// handles conversion into envoy auth types
// based on https://github.com/solo-io/gloo/blob/main/projects/gloo/pkg/utils/ssl.go#L76

var noKeyFoundMsg = "no key ca.crt found"

func ResolveUpstreamSslConfig(cm *corev1.ConfigMap, validation *tlsv3.CertificateValidationContext, sni string) (*tlsv3.UpstreamTlsContext, error) {
	common, err := ResolveCommonSslConfig(cm, validation, false)
	if err != nil {
		return nil, err
	}

	return &tlsv3.UpstreamTlsContext{
		CommonTlsContext: common,
		Sni:              sni,
	}, nil
}

func ResolveCommonSslConfig(cm *corev1.ConfigMap, validation *tlsv3.CertificateValidationContext, mustHaveCert bool) (*tlsv3.CommonTlsContext, error) {
	caCrt, err := getSslSecrets(cm)
	if err != nil {
		return nil, err
	}

	// TODO: should we do some validation on the CA?
	caCrtData := corev3.DataSource{
		Specifier: &corev3.DataSource_InlineString{
			InlineString: caCrt,
		},
	}

	tlsContext := &tlsv3.CommonTlsContext{
		// default params
		TlsParams: &tlsv3.TlsParameters{},
	}
	validation.TrustedCa = &caCrtData
	validationCtx := &tlsv3.CommonTlsContext_ValidationContext{
		ValidationContext: validation,
	}

	tlsContext.ValidationContextType = validationCtx
	return tlsContext, nil
}

func getSslSecrets(cm *corev1.ConfigMap) (string, error) {
	caCrt, ok := cm.Data["ca.crt"]
	if !ok {
		return "", errors.New(noKeyFoundMsg)
	}

	return caCrt, nil
}
