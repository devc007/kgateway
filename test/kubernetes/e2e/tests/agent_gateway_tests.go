package tests

import (
	"github.com/kgateway-dev/kgateway/v2/test/kubernetes/e2e"
	"github.com/kgateway-dev/kgateway/v2/test/kubernetes/e2e/features/agentgateway"
)

func AgentGatewaySuiteRunner() e2e.SuiteRunner {
	agentgatewaySuiteRunner := e2e.NewSuiteRunner(false)
	agentgatewaySuiteRunner.Register("AgentGateway", agentgateway.NewTestingSuite)

	return agentgatewaySuiteRunner
}
