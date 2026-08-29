package firewall

import (
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
)

func composedCoverageSite(t *testing.T, mode string) model.Site {
	t.Helper()
	config := model.ConfigFromSite(model.NewSite("coverage", "age1coverage", mode))
	if mode == model.GatewayModeExternal {
		disabled := false
		config.Modules.Firewall = &model.ToggleModuleConfig{Enabled: &disabled}
	}
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	return site
}

func TestValidateNetworkIntentCoverageMatchesManagedGeneratedPolicy(t *testing.T) {
	site := composedCoverageSite(t, model.GatewayModeManaged)
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateNetworkIntentCoverage(site, plan); err != nil {
		t.Fatalf("complete generated policy failed coverage validation: %v", err)
	}

	for index, rule := range plan.Rules {
		if strings.HasPrefix(rule.Name, "module monitoring ") {
			plan.Rules = append(plan.Rules[:index], plan.Rules[index+1:]...)
			if err := ValidateNetworkIntentCoverage(site, plan); err == nil || !strings.Contains(err.Error(), "monitoring") {
				t.Fatalf("missing module rule was not rejected: %v", err)
			}
			return
		}
	}
	t.Fatal("test site had no monitoring network rule")
}

func TestValidateNetworkIntentCoverageExternalModeOwnsContractGenerationOnly(t *testing.T) {
	site := composedCoverageSite(t, model.GatewayModeExternal)
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateNetworkIntentCoverage(site, plan); err != nil {
		t.Fatalf("external contract generation failed coverage validation: %v", err)
	}
}
