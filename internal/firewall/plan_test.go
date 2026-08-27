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
	if len(plan.Interfaces) != 7 {
		t.Fatalf("got %d gateway interfaces, want 7", len(plan.Interfaces))
	}
	want := []Interface{
		{Role: "WAN", Name: "wan0", MAC: "02:00:00:00:01:01", Bridge: "vmbr0", Address: "dhcp", Method: "dhcp"},
		{Role: "TRUSTED", Name: "trusted0", MAC: "02:00:00:00:01:02", Bridge: "vmbr1", VLAN: 30, Address: "10.10.30.1/24", Method: "static"},
		{Role: "SERVERS", Name: "servers0", MAC: "02:00:00:00:01:03", Bridge: "vmbr1", VLAN: 20, Address: "10.10.20.1/24", Method: "static"},
		{Role: "SANDBOX", Name: "sandbox0", MAC: "02:00:00:00:01:04", Bridge: "vmbr1", VLAN: 40, Address: "10.10.40.1/24", Method: "static"},
		{Role: "MGMT", Name: "mgmt0", MAC: "02:00:00:00:01:05", Bridge: "vmbr1", VLAN: 99, Address: "10.10.99.1/24", Method: "static"},
		{Role: "TRANSIT", Name: "transit0", MAC: "02:00:00:00:01:06", Bridge: "vmbr1", VLAN: 5, Address: "10.10.5.1/24", Method: "static"},
		{Role: "INFRA", Name: "infra0", MAC: "02:00:00:00:01:07", Bridge: "vmbr1", VLAN: 10, Address: "10.10.10.1/24", Method: "static"},
	}
	for i := range want {
		if plan.Interfaces[i] != want[i] {
			t.Fatalf("interface %d = %#v, want %#v", i, plan.Interfaces[i], want[i])
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
		"SANDBOX-INFRA-DROP",
		"transit_net",
		"infra_net",
		"TRANSIT-INFRA-DROP",
		"TRANSIT-TRUSTED-DROP",
		"TRANSIT-SERVERS-DROP",
		"TRANSIT-SANDBOX-DROP",
		"TRANSIT-MGMT-DROP",
		"TRANSIT-ADMIN-DROP",
		"TRANSIT-INTERNET-DROP",
		"TO-TRANSIT-DROP",
		"table ip boetticher_nat",
		"oifname \"wan0\" ip saddr 10.10.40.0/24 masquerade",
		"oifname \"wan0\" ip saddr 10.10.10.0/24 masquerade",
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
	if len(plan.Rules) == 0 || len(plan.DHCP) != 2 {
		t.Fatalf("external contract lost policy or DHCP requirements: %#v", plan)
	}
	if plan.DHCP[0].Zone != "TRUSTED" || plan.DHCP[0].Network != "10.10.30.0/24" || plan.DHCP[1].Zone != "SANDBOX" || plan.DHCP[1].Network != "10.10.40.0/24" {
		t.Fatalf("external contract has unexpected DHCP scopes: %#v", plan.DHCP)
	}
	contract, err := RenderExternalContract(model.NewSite("installation", "age1example", model.GatewayModeExternal), plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"TRANSIT", "INFRA", "`transit`", "`infrastructure`", "VLAN 5", "VLAN 10", "VLAN 30", "VLAN 40", "VLAN 99", "10.10.5.0/24", "10.10.10.0/24", "10.10.30.0/24", "10.10.40.0/24", "enforcement is NOT ACTIVE", "Required routes", "Required allows", "Required denies", "Source address expectations", "Module-advertised routes: none"} {
		if !strings.Contains(contract, expected) {
			t.Errorf("external contract missing %q", expected)
		}
	}
	if _, err := RenderNFT(plan); err == nil {
		t.Fatal("external mode rendered a managed nftables ruleset")
	}
}
