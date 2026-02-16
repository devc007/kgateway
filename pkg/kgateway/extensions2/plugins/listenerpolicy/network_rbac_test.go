package listenerpolicy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sharedv1alpha1 "github.com/kgateway-dev/kgateway/v2/api/v1alpha1/shared"
)

func TestTranslateNetworkRBAC_NilInput(t *testing.T) {
	result, err := translateNetworkRBAC(nil)
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestTranslateNetworkRBAC_AllowAction(t *testing.T) {
	rbac := &sharedv1alpha1.Authorization{
		Policy: sharedv1alpha1.AuthorizationPolicy{
			MatchExpressions: []sharedv1alpha1.CELExpression{
				"connection.source_address.matches('10.0.0.0/8')",
			},
		},
		Action: sharedv1alpha1.AuthorizationPolicyActionAllow,
	}

	result, err := translateNetworkRBAC(rbac)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "network_rbac", result.StatPrefix)
	assert.NotNil(t, result.Matcher)
}

func TestTranslateNetworkRBAC_DenyAction(t *testing.T) {
	rbac := &sharedv1alpha1.Authorization{
		Policy: sharedv1alpha1.AuthorizationPolicy{
			MatchExpressions: []sharedv1alpha1.CELExpression{
				"connection.source_address.matches('192.0.2.0/24')",
			},
		},
		Action: sharedv1alpha1.AuthorizationPolicyActionDeny,
	}

	result, err := translateNetworkRBAC(rbac)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotNil(t, result.Matcher)
}

func TestTranslateNetworkRBAC_MultipleExpressions(t *testing.T) {
	rbac := &sharedv1alpha1.Authorization{
		Policy: sharedv1alpha1.AuthorizationPolicy{
			MatchExpressions: []sharedv1alpha1.CELExpression{
				"connection.source_address.matches('10.0.0.0/8')",
				"connection.source_address.matches('192.168.0.0/16')",
			},
		},
		Action: sharedv1alpha1.AuthorizationPolicyActionAllow,
	}

	result, err := translateNetworkRBAC(rbac)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotNil(t, result.Matcher)
}

func TestTranslateNetworkRBAC_EmptyExpressions(t *testing.T) {
	rbac := &sharedv1alpha1.Authorization{
		Policy: sharedv1alpha1.AuthorizationPolicy{
			MatchExpressions: []sharedv1alpha1.CELExpression{},
		},
		Action: sharedv1alpha1.AuthorizationPolicyActionAllow,
	}

	result, err := translateNetworkRBAC(rbac)
	require.NoError(t, err)
	require.NotNil(t, result)
	// Should create a deny-all RBAC when no expressions
	assert.NotNil(t, result.Rules)
}
