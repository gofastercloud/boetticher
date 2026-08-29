package firewall

import (
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestUserFirewallRulesAreDeterministicAndHaveStableComments(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	site.UserFirewallRules = []model.UserFirewallRule{
		{ID: "ufr-b", Source: "TRUSTED", Destination: "10.10.20.62/32", Protocol: "udp", Ports: []string{"53"}},
		{ID: "ufr-a", Source: "TRUSTED", Destination: "10.10.20.61/32", Protocol: "tcp", Ports: []string{"443"}},
	}
	one, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	ruleset, err := RenderNFT(one)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ruleset, `comment "boetticher:user-rule:ufr-a:tcp"`) || !strings.Contains(ruleset, `comment "boetticher:user-rule:ufr-b:udp"`) {
		t.Fatalf("stable user rule comments missing: %s", ruleset)
	}
	if strings.Index(ruleset, "ufr-a") > strings.Index(ruleset, "ufr-b") {
		t.Fatal("user firewall rules are not ordered by stable ID")
	}
	two, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	ruleset2, err := RenderNFT(two)
	if err != nil {
		t.Fatal(err)
	}
	if ruleset != ruleset2 {
		t.Fatal("user firewall rendering is not deterministic")
	}
}

func TestExternalContractIncludesUserFirewallIntentWithoutMutation(t *testing.T) {
	site := model.NewSite("installation", "age1example", model.GatewayModeExternal)
	site.UserFirewallRules = []model.UserFirewallRule{{ID: "ufr-a", Source: "TRUSTED", Destination: "10.10.20.61/32", Protocol: "tcp", Ports: []string{"443"}}}
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	contract, err := RenderExternalContract(site, plan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(contract, "ufr-a") || strings.Contains(contract, "nft ") {
		t.Fatalf("external contract did not render intent-only user rule: %s", contract)
	}
}

func TestPlanRejectsPersistedUserRuleWithInvalidSelector(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	site.UserFirewallRules = []model.UserFirewallRule{{ID: "ufr-unrenderable", Source: "10.10.20.61", Destination: "10.10.20.62/32", Protocol: "tcp", Ports: []string{"443"}}}
	if _, err := PlanFromSite(site); err == nil {
		t.Fatal("invalid persisted selector was silently dropped")
	}
}
