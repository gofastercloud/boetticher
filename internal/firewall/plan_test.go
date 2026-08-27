package firewall

import (
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestManagedPlanUsesOneUntaggedFirewallInterfacePerZone(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Interfaces) != 5 {
		t.Fatalf("got %d gateway interfaces, want 5", len(plan.Interfaces))
	}
	want := []Interface{
		{Role: "WAN", Name: "wan0", MAC: "02:00:00:00:01:01", Bridge: "vmbr0", Address: "dhcp", Method: "dhcp"},
		{Role: "TRUSTED", Name: "trusted0", MAC: "02:00:00:00:01:02", Bridge: "vmbr1", VLAN: 10, Address: "10.10.10.1/24", Method: "static"},
		{Role: "SERVERS", Name: "servers0", MAC: "02:00:00:00:01:03", Bridge: "vmbr1", VLAN: 20, Address: "10.10.20.1/24", Method: "static"},
		{Role: "SANDBOX", Name: "sandbox0", MAC: "02:00:00:00:01:04", Bridge: "vmbr1", VLAN: 50, Address: "10.10.50.1/24", Method: "static"},
		{Role: "MGMT", Name: "mgmt0", MAC: "02:00:00:00:01:05", Bridge: "vmbr1", VLAN: 99, Address: "10.10.99.1/24", Method: "static"},
	}
	for i := range want {
		if plan.Interfaces[i] != want[i] {
			t.Fatalf("interface %d = %#v, want %#v", i, plan.Interfaces[i], want[i])
		}
	}
}

func TestManagedPlanRendersValidDHCPPools(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"10.10.10.100-10.10.10.199",
		"10.10.20.100-10.10.20.199",
		"10.10.50.100-10.10.50.199",
		"",
	}
	for i, pool := range want {
		if plan.DHCP[i].Pool != pool {
			t.Fatalf("DHCP pool %d = %q, want %q", i, plan.DHCP[i].Pool, pool)
		}
	}
}

func TestManagedRulesetIsDeterministicAndFailClosed(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	first, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	a, err := RenderNFT(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := RenderNFT(second)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("identical sites rendered different nftables rulesets")
	}
	if err := ValidateNFT(a); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"policy drop",
		"ct state established,related accept",
		"SANDBOX-TRUSTED-DROP",
		"SANDBOX-SERVERS-DROP",
		"SANDBOX-MGMT-DROP",
		"table ip boetticher_nat",
		"oifname \"wan0\" ip saddr 10.10.50.0/24 masquerade",
	} {
		if !strings.Contains(a, expected) {
			t.Errorf("ruleset missing %q", expected)
		}
	}
	if strings.Index(a, "SANDBOX-MGMT-DROP") > strings.Index(a, "iifname \"sandbox0\" oifname \"wan0\"") {
		t.Error("SANDBOX internal deny occurs after Internet egress")
	}
}

func TestExternalPlanHasPolicyButNoManagedInterfaces(t *testing.T) {
	plan, err := PlanFromSite(model.NewSite("installation", "age1example", model.GatewayModeExternal))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Mode != model.GatewayModeExternal || len(plan.Interfaces) != 0 {
		t.Fatalf("unexpected external gateway plan: %#v", plan)
	}
	if len(plan.Rules) == 0 || len(plan.DHCP) != 4 {
		t.Fatalf("external contract lost policy or DHCP requirements: %#v", plan)
	}
	if _, err := RenderNFT(plan); err == nil {
		t.Fatal("external mode rendered a managed nftables ruleset")
	}
}
