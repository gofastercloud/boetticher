package firewall

import (
	"reflect"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
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
	if len(plan.Interfaces) != len(want) {
		t.Fatalf("got %d interfaces, want exact fixed WAN plus six internal interfaces", len(plan.Interfaces))
	}
	for i := range want {
		if plan.Interfaces[i] != want[i] {
			t.Fatalf("interface %d = %#v, want %#v", i, plan.Interfaces[i], want[i])
		}
	}
}

func TestServersDHCPIsReservationOnly(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	site.DHCPReservations = []model.DHCPReservation{{Zone: "SERVERS", Hostname: "app-01", Address: "10.10.20.61", MAC: "02:00:00:00:02:61"}}
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.DHCP) != 3 || plan.DHCP[0].Zone != "SERVERS" || plan.DHCP[0].Pool != "" || len(plan.DHCP[0].Reservations) != 1 {
		t.Fatalf("unexpected SERVERS DHCP contract: %#v", plan.DHCP)
	}
	reservation := plan.DHCP[0].Reservations[0]
	if reservation.Hostname != "app-01" || reservation.Address != "10.10.20.61" || reservation.MAC != "02:00:00:00:02:61" {
		t.Fatalf("unexpected SERVERS reservation: %#v", reservation)
	}
	if plan.DHCP[1].Pool != "10.10.30.100-10.10.30.199" || plan.DHCP[2].Pool != "10.10.40.100-10.10.40.199" {
		t.Fatalf("existing dynamic pools changed unexpectedly: %#v", plan.DHCP)
	}
	ruleset, err := RenderNFT(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ruleset, `iifname { "trusted0", "servers0", "sandbox0" } udp dport 67`) {
		t.Fatal("managed firewall does not permit SERVERS DHCP requests")
	}
	if !strings.Contains(ruleset, `iifname "infra0" oifname "wan0" ip saddr @infra_net udp dport { 53, 123, 853 }`) {
		t.Fatal("managed firewall does not permit INFRA NTP egress")
	}
}

func TestComposedModuleIntentsAreNarrowManagedAllows(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	tailnetEnabled, litellmEnabled := true, true
	config.Modules.TailnetRouter = &model.ToggleModuleConfig{Enabled: &tailnetEnabled}
	config.Modules.LiteLLM = &model.LiteLLMModuleConfig{
		Enabled:   &litellmEnabled,
		Upstreams: []model.LiteLLMUpstreamConfig{{Name: "openrouter", BaseURL: "https://openrouter.ai/api/v1", APIKeySecret: "openrouter_api_key"}},
		Models:    []model.LiteLLMModelConfig{{Alias: "selected-alias", Upstream: "openrouter", Model: "selected/openrouter-model"}},
	}
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	ruleset, err := RenderNFT(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"10.10.5.10/32 ip daddr 10.10.20.60/32 tcp dport 443",
		"10.10.5.10/32 ip daddr 10.10.10.30/32 tcp dport 443",
		"10.10.5.10/32 ip daddr 10.10.10.20/32 tcp dport 443",
		"10.10.10.20/32 ip daddr 10.10.99.5/32 tcp dport 8006",
		"10.10.99.5/32 ip daddr 10.10.10.40/32 tcp dport 19532",
		"10.10.20.60/32 ip daddr openrouter.ai tcp dport 443",
		"set module_guest_sources { type ipv4_addr; elements = {",
		"10.10.10.20, 10.10.20.60, 10.10.5.10",
		"iifname \"servers0\" ip saddr != @module_guest_sources oifname \"wan0\"",
		"arbitrary-egress-drop",
	} {
		if !strings.Contains(ruleset, expected) {
			t.Errorf("managed module policy missing %q:\n%s", expected, ruleset)
		}
	}
	if strings.Index(ruleset, "10.10.5.10/32 ip daddr 10.10.20.60/32") > strings.Index(ruleset, "TRANSIT-SERVERS-DROP") {
		t.Fatal("narrow tailnet-to-LiteLLM allow occurs after the TRANSIT default deny")
	}
	if strings.Contains(ruleset, `iifname "transit0" ip daddr @servers_net accept`) {
		t.Fatal("managed module policy contains a broad TRANSIT-to-SERVERS allow")
	}
	if strings.Contains(ruleset, "10051") {
		t.Fatal("Pulse-based monitoring policy retains the removed Zabbix port")
	}
	if strings.Contains(ruleset, `iifname "servers0" oifname "wan0" ip saddr @servers_net tcp dport { 53, 80, 443, 853 } counter accept`) {
		t.Fatal("module-owned SERVERS guests inherit the unrestricted zone Internet allow")
	}
}

func TestQualifiedModuleLoggingIntentResolvesCollector(t *testing.T) {
	rule := policyRuleForIntent(model.NewDefaultSite("installation", "age1example"), "logging", model.NetworkIntent{
		Source: "lab-portal-01", Destination: "logs.lab.home.arpa", Protocol: "tcp", Ports: []string{"19532"}, Purpose: "native journal upload",
	})
	if rule.DestinationCIDR != "10.10.10.40/32" || rule.To != "INFRA" {
		t.Fatalf("qualified logging destination resolved incorrectly: %#v", rule)
	}
}

func TestCoreModuleGuestsRetainBaselinePolicy(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan.ModuleSources, []string{"10.10.10.20/32"}) {
		t.Fatalf("Pulse source-specific policy is incomplete: %v", plan.ModuleSources)
	}
	ruleset, err := RenderNFT(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ruleset, "set module_guest_sources { type ipv4_addr; elements = { 10.10.10.20 }") {
		t.Fatal("Pulse source-specific policy did not emit its source isolation set")
	}
	if !strings.Contains(ruleset, `iifname "servers0" ip saddr != @module_guest_sources oifname "wan0" ip saddr @servers_net tcp dport { 53, 80, 443, 853 } counter accept`) {
		t.Fatal("existing SERVERS baseline Internet policy was removed")
	}
}

func TestModuleGuestSourcesRequireSourceSpecificIntent(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	tailnetEnabled, litellmEnabled := true, true
	config.Modules.TailnetRouter = &model.ToggleModuleConfig{Enabled: &tailnetEnabled}
	config.Modules.LiteLLM = &model.LiteLLMModuleConfig{
		Enabled:   &litellmEnabled,
		Upstreams: []model.LiteLLMUpstreamConfig{{Name: "openrouter", BaseURL: "https://openrouter.ai/api/v1", APIKeySecret: "openrouter_api_key"}},
		Models:    []model.LiteLLMModelConfig{{Alias: "selected-alias", Upstream: "openrouter", Model: "selected/openrouter-model"}},
	}
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.10.10.20/32", "10.10.20.60/32", "10.10.5.10/32"}
	if !reflect.DeepEqual(plan.ModuleSources, want) {
		t.Fatalf("module guest sources = %v, want only source-intent guests %v", plan.ModuleSources, want)
	}
}

func TestExternalComposedContractCarriesModuleRouteAndOperatorBoundary(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeExternal))
	firewallDisabled, tailnetEnabled, litellmEnabled := false, true, true
	config.Modules.Firewall = &model.ToggleModuleConfig{Enabled: &firewallDisabled}
	config.Modules.TailnetRouter = &model.ToggleModuleConfig{Enabled: &tailnetEnabled}
	config.Modules.LiteLLM = &model.LiteLLMModuleConfig{
		Enabled:   &litellmEnabled,
		Upstreams: []model.LiteLLMUpstreamConfig{{Name: "openrouter", BaseURL: "https://openrouter.ai/api/v1", APIKeySecret: "openrouter_api_key"}},
		Models:    []model.LiteLLMModelConfig{{Alias: "selected-alias", Upstream: "openrouter", Model: "selected/openrouter-model"}},
	}
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	contract, err := RenderExternalContract(site, plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"10.10.0.0/16", "10.10.5.10", "10.10.5.0/24", "10.10.5.1", "subnet-route", "route approval", "accept-dns=false", "LiteLLM HTTPS", "portal HTTPS", "monitoring HTTPS", "openrouter.ai", "required return routing", "Proxmox API", "SSH", "enforcement is NOT ACTIVE", "operator implementation responsibility"} {
		if !strings.Contains(strings.ToLower(contract), strings.ToLower(expected)) {
			t.Errorf("external module contract missing %q", expected)
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
	if strings.Index(a, "SANDBOX-MGMT-DROP") > strings.Index(a, "forward-sandbox-internet") {
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
	if len(plan.Rules) == 0 || len(plan.DHCP) != 3 {
		t.Fatalf("external contract lost policy or DHCP requirements: %#v", plan)
	}
	if plan.DHCP[0].Zone != "SERVERS" || plan.DHCP[0].Network != "10.10.20.0/24" || plan.DHCP[1].Zone != "TRUSTED" || plan.DHCP[1].Network != "10.10.30.0/24" || plan.DHCP[2].Zone != "SANDBOX" || plan.DHCP[2].Network != "10.10.40.0/24" {
		t.Fatalf("external contract has unexpected DHCP scopes: %#v", plan.DHCP)
	}
	contract, err := RenderExternalContract(model.NewSite("installation", "age1example", model.GatewayModeExternal), plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"TRANSIT", "INFRA", "`transit`", "`infrastructure`", "VLAN 5", "VLAN 10", "VLAN 20", "VLAN 30", "VLAN 40", "VLAN 99", "10.10.5.0/24", "10.10.10.0/24", "10.10.20.0/24", "10.10.30.0/24", "10.10.40.0/24", "enforcement is NOT ACTIVE", "Required routes", "Required allows", "Required denies", "Source address expectations", "Module-advertised routes: none"} {
		if !strings.Contains(contract, expected) {
			t.Errorf("external contract missing %q", expected)
		}
	}
	if _, err := RenderNFT(plan); err == nil {
		t.Fatal("external mode rendered a managed nftables ruleset")
	}
}
