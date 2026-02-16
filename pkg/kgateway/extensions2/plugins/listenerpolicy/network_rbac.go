package listenerpolicy

import (
	"fmt"

	"cel.dev/expr"
	cncfcorev3 "github.com/cncf/xds/go/xds/core/v3"
	cncfmatcherv3 "github.com/cncf/xds/go/xds/type/matcher/v3"
	cncftypev3 "github.com/cncf/xds/go/xds/type/v3"
	envoyrbacv3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	envoynetworkrbac "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/rbac/v3"
	"github.com/google/cel-go/cel"
	"google.golang.org/protobuf/proto"

	sharedv1alpha1 "github.com/kgateway-dev/kgateway/v2/api/v1alpha1/shared"
	"github.com/kgateway-dev/kgateway/v2/pkg/kgateway/utils"
)

// translateNetworkRBAC converts the Authorization spec to Envoy network RBAC filter configuration.
// Network RBAC is evaluated at the connection level, before any HTTP processing occurs.
func translateNetworkRBAC(rbac *sharedv1alpha1.Authorization) (*envoynetworkrbac.RBAC, error) {
	if rbac == nil {
		return nil, nil
	}

	var errs []error

	// Create matcher-based RBAC configuration
	var matchers []*cncfmatcherv3.Matcher_MatcherList_FieldMatcher

	if len(rbac.Policy.MatchExpressions) > 0 {
		matcher, err := createNetworkCELMatcher(rbac.Policy.MatchExpressions, rbac.Action)
		if err != nil {
			errs = append(errs, err)
		} else {
			matchers = append(matchers, matcher)
		}
	}

	if len(matchers) == 0 {
		// If no CEL matchers, create a simple deny-all RBAC
		return &envoynetworkrbac.RBAC{
			Rules: &envoyrbacv3.RBAC{
				Action:   envoyrbacv3.RBAC_DENY,
				Policies: map[string]*envoyrbacv3.Policy{},
			},
			StatPrefix: "network_rbac",
		}, nil
	}

	// Determine default action based on policy action
	// If policy action is Allow, default should be Deny (and vice versa)
	defaultAction := envoyrbacv3.RBAC_DENY
	if rbac.Action == sharedv1alpha1.AuthorizationPolicyActionDeny {
		defaultAction = envoyrbacv3.RBAC_ALLOW
	}

	celMatcher := &cncfmatcherv3.Matcher{
		MatcherType: &cncfmatcherv3.Matcher_MatcherList_{
			MatcherList: &cncfmatcherv3.Matcher_MatcherList{
				Matchers: matchers,
			},
		},
		OnNoMatch: createDefaultNetworkAction(defaultAction),
	}

	res := &envoynetworkrbac.RBAC{
		Matcher:    celMatcher,
		StatPrefix: "network_rbac",
	}

	if len(errs) > 0 {
		return res, fmt.Errorf("network RBAC policy encountered CEL matcher errors: %v", errs)
	}
	return res, nil
}

// createNetworkCELMatcher creates a CEL matcher for network-level attributes.
// Network RBAC has access to connection-level attributes like source IP, TLS session info, etc.
func createNetworkCELMatcher(celExprs []sharedv1alpha1.CELExpression, action sharedv1alpha1.AuthorizationPolicyAction) (*cncfmatcherv3.Matcher_MatcherList_FieldMatcher, error) {
	if len(celExprs) == 0 {
		return nil, fmt.Errorf("no CEL expressions provided")
	}

	// Create CEL match input for network attributes
	// This uses the network-level CEL data input which has access to connection properties
	celMatchInput, err := utils.MessageToAny(&cncfmatcherv3.HttpAttributesCelMatchInput{})
	if err != nil {
		return nil, err
	}

	celMatchInputConfig := &cncfcorev3.TypedExtensionConfig{
		Name:        "envoy.matching.inputs.cel_data_input",
		TypedConfig: celMatchInput,
	}

	// Create parsed expression
	env, err := cel.NewEnv()
	if err != nil {
		logger.Error("failed to create CEL environment", "err", err.Error())
		return nil, err
	}

	var predicate *cncfmatcherv3.Matcher_MatcherList_Predicate
	if len(celExprs) == 1 {
		// Single expression - use SinglePredicate
		celDevParsed, err := parseNetworkCELExpression(env, celExprs[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse CEL expression: %w", err)
		}

		matcher := &cncfmatcherv3.CelMatcher{
			ExprMatch: &cncftypev3.CelExpression{
				CelExprParsed: celDevParsed,
			},
		}
		pb, err := utils.MessageToAny(matcher)
		if err != nil {
			return nil, err
		}

		typedCelMatchConfig := &cncfcorev3.TypedExtensionConfig{
			Name:        "envoy.matching.matchers.cel_matcher",
			TypedConfig: pb,
		}
		predicate = &cncfmatcherv3.Matcher_MatcherList_Predicate{
			MatchType: &cncfmatcherv3.Matcher_MatcherList_Predicate_SinglePredicate_{
				SinglePredicate: &cncfmatcherv3.Matcher_MatcherList_Predicate_SinglePredicate{
					Input: celMatchInputConfig,
					Matcher: &cncfmatcherv3.Matcher_MatcherList_Predicate_SinglePredicate_CustomMatch{
						CustomMatch: typedCelMatchConfig,
					},
				},
			},
		}
	} else {
		// Multiple expressions - create a list of predicates
		var predicates []*cncfmatcherv3.Matcher_MatcherList_Predicate

		for _, celExpr := range celExprs {
			celDevParsed, err := parseNetworkCELExpression(env, celExpr)
			if err != nil {
				return nil, fmt.Errorf("failed to parse CEL expression: %w", err)
			}

			matcher := &cncfmatcherv3.CelMatcher{
				ExprMatch: &cncftypev3.CelExpression{
					CelExprParsed: celDevParsed,
				},
			}
			pb, err := utils.MessageToAny(matcher)
			if err != nil {
				return nil, err
			}

			typedCelMatchConfig := &cncfcorev3.TypedExtensionConfig{
				Name:        "envoy.matching.matchers.cel_matcher",
				TypedConfig: pb,
			}

			singlePredicate := &cncfmatcherv3.Matcher_MatcherList_Predicate{
				MatchType: &cncfmatcherv3.Matcher_MatcherList_Predicate_SinglePredicate_{
					SinglePredicate: &cncfmatcherv3.Matcher_MatcherList_Predicate_SinglePredicate{
						Input: celMatchInputConfig,
						Matcher: &cncfmatcherv3.Matcher_MatcherList_Predicate_SinglePredicate_CustomMatch{
							CustomMatch: typedCelMatchConfig,
						},
					},
				},
			}
			predicates = append(predicates, singlePredicate)
		}

		// Create an OR predicate that contains all the single predicates
		predicate = &cncfmatcherv3.Matcher_MatcherList_Predicate{
			MatchType: &cncfmatcherv3.Matcher_MatcherList_Predicate_OrMatcher{
				OrMatcher: &cncfmatcherv3.Matcher_MatcherList_Predicate_PredicateList{
					Predicate: predicates,
				},
			},
		}
	}

	// Determine the action based on policy action
	var onMatchAction *cncfmatcherv3.Matcher_OnMatch
	if action == sharedv1alpha1.AuthorizationPolicyActionDeny {
		onMatchAction = createNetworkMatchAction(envoyrbacv3.RBAC_DENY)
	} else {
		onMatchAction = createNetworkMatchAction(envoyrbacv3.RBAC_ALLOW)
	}

	return &cncfmatcherv3.Matcher_MatcherList_FieldMatcher{
		Predicate: predicate,
		OnMatch:   onMatchAction,
	}, nil
}

// createNetworkMatchAction creates an RBAC action for network-level matching
func createNetworkMatchAction(action envoyrbacv3.RBAC_Action) *cncfmatcherv3.Matcher_OnMatch {
	actionName := "allow-connection"
	if action == envoyrbacv3.RBAC_DENY {
		actionName = "deny-connection"
	}

	rbacAction := &envoyrbacv3.Action{
		Name:   actionName,
		Action: action,
	}

	actionAny, _ := utils.MessageToAny(rbacAction)

	return &cncfmatcherv3.Matcher_OnMatch{
		OnMatch: &cncfmatcherv3.Matcher_OnMatch_Action{
			Action: &cncfcorev3.TypedExtensionConfig{
				Name:        "envoy.filters.rbac.action",
				TypedConfig: actionAny,
			},
		},
	}
}

// createDefaultNetworkAction creates the default action when no matchers match
func createDefaultNetworkAction(action envoyrbacv3.RBAC_Action) *cncfmatcherv3.Matcher_OnMatch {
	actionName := "allow-connection"
	if action == envoyrbacv3.RBAC_DENY {
		actionName = "deny-connection"
	}

	rbacAction := &envoyrbacv3.Action{
		Name:   actionName,
		Action: action,
	}

	actionAny, _ := utils.MessageToAny(rbacAction)

	return &cncfmatcherv3.Matcher_OnMatch{
		OnMatch: &cncfmatcherv3.Matcher_OnMatch_Action{
			Action: &cncfcorev3.TypedExtensionConfig{
				Name:        "action",
				TypedConfig: actionAny,
			},
		},
	}
}

// parseNetworkCELExpression takes a CEL expression string and converts it to a parsed expression
// for use in network-level Envoy matchers.
func parseNetworkCELExpression(env *cel.Env, celExpr sharedv1alpha1.CELExpression) (*expr.ParsedExpr, error) {
	if env == nil {
		return nil, fmt.Errorf("CEL environment is nil")
	}

	ast, iss := env.Parse(string(celExpr))
	if iss.Err() != nil {
		logger.Error("parse error", "err", iss.Err())
		return nil, iss.Err()
	}

	parsedExpr, err := cel.AstToParsedExpr(ast)
	if err != nil {
		logger.Error("failed to convert AST to parsed expression", "err", err.Error())
		return nil, err
	}

	// Marshal from google.golang.org/genproto
	data, err := proto.Marshal(parsedExpr)
	if err != nil {
		logger.Error("marshal err", "err", err.Error())
		return nil, err
	}

	// Unmarshal into cel.dev/expr/v1alpha1
	var celDevParsed expr.ParsedExpr
	if err := proto.Unmarshal(data, &celDevParsed); err != nil {
		logger.Error("unmarshal err", "err", err.Error())
		return nil, err
	}

	return &celDevParsed, nil
}
