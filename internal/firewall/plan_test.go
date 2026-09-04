package firewall

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	networkmodel "github.com/gofastercloud/boetticher/internal/network"
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

func TestGatewayInterfaceConfigurationDigestsMatchRenderedFiles(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	digests := GatewayInterfaceConfigurationDigests(plan)
	if len(digests) != len(plan.Interfaces) {
		t.Fatalf("got %d interface configuration digests, want %d", len(digests), len(plan.Interfaces))
	}
	for _, iface := range plan.Interfaces {
		got, ok := digests[iface.Name]
		if !ok || len(got.Link) != 64 || len(got.Network) != 64 {
			t.Fatalf("missing valid configuration digests for %s: %#v", iface.Name, got)
		}
		link := fmt.Sprintf("[Match]\nMACAddress=%s\n\n[Link]\nName=%s\n", iface.MAC, iface.Name)
		network := fmt.Sprintf("[Match]\nName=%s\n\n[Network]\n", iface.Name)
		if iface.Method == "dhcp" {
			network += "DHCP=ipv4\n"
		} else {
			network += fmt.Sprintf("Address=%s\n", iface.Address)
		}
		network += "IPv6AcceptRA=no\nLinkLocalAddressing=no\n"
		if got.Link != sha256Hex(link) || got.Network != sha256Hex(network) {
			t.Fatalf("configuration digest mismatch for %s: %#v", iface.Name, got)
		}
	}
}

func TestRulesetDigestIsStableAndContentAddressed(t *testing.T) {
	first := RulesetDigest("table inet boetticher {}\n")
	second := RulesetDigest("table inet boetticher {}\n")
	if first != second || len(first) != 64 {
		t.Fatalf("identical rulesets produced different or invalid digests: %q %q", first, second)
	}
	if first == RulesetDigest("table inet boetticher { counter }\n") {
		t.Fatal("different rulesets produced the same digest")
	}
}

func TestManagedFirewallTelemetryContractAndSemanticCounterComments(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Telemetry.Enabled || plan.Telemetry.ListenAddress != TelemetryListenAddress || plan.Telemetry.Port != TelemetryPort || len(plan.Telemetry.AllowedSources) != 1 || plan.Telemetry.AllowedSources[0] != TelemetryPulseSource {
		t.Fatalf("unexpected managed firewall telemetry contract: %#v", plan.Telemetry)
	}
	if err := plan.Telemetry.Validate(); err != nil {
		t.Fatal(err)
	}
	ruleset, err := RenderNFT(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ruleset, `iifname "infra0" ip saddr 10.10.10.20 tcp dport 9765 counter accept comment "boetticher:allow:input-firewall-telemetry"`) {
		t.Fatal("managed firewall telemetry API exposure is not exact")
	}
	for _, line := range strings.Split(ruleset, "\n") {
		if strings.Contains(line, " counter ") && !strings.Contains(line, `comment "boetticher:allow:`) && !strings.Contains(line, `comment "boetticher:deny:`) && !strings.Contains(line, `comment "boetticher:drop:`) {
			t.Fatalf("counter rule lacks a semantic Boetticher comment: %s", line)
		}
	}
}

func TestExternalFirewallTelemetryContractIsDisabled(t *testing.T) {
	plan, err := PlanFromSite(model.NewSite("installation", "age1example", model.GatewayModeExternal))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Telemetry.Enabled || len(plan.Telemetry.AllowedSources) != 0 {
		t.Fatalf("external gateway unexpectedly owns firewall telemetry: %#v", plan.Telemetry)
	}
}

func TestDynamicFirewallTelemetryIDsUseSafeStableTokens(t *testing.T) {
	got := safeRuleToken(`module "drop"/../unsafe value`)
	if got != "module__drop_____unsafe_value" || len(got) > 128 {
		t.Fatalf("unsafe dynamic rule token = %q", got)
	}
	if _, err := SemanticCounterComment("allow", got); err != nil {
		t.Fatalf("sanitized dynamic rule token is not a valid semantic ID: %v", err)
	}
}

func TestPublishedDNSIsBoundedToObservedUpstreamPrefixAndAddress(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	site.Gateway.Publish = []model.GatewayPublication{{Service: "dns"}}
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Publications) != 2 || plan.Publications[0].Destination != "lab-dns-01" || plan.Publications[0].DestinationCIDR != "10.10.10.10/32" {
		t.Fatalf("unexpected publication plan: %#v", plan.Publications)
	}
	if _, err := RenderNFT(plan); err == nil {
		t.Fatal("publication rendered without an observed upstream lease")
	}
	safeRuleset, err := RenderSafeNFT(plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(safeRuleset, "dnat to") || strings.Contains(safeRuleset, "boetticher:publish") {
		t.Fatal("safe publication ruleset unexpectedly contains an inactive DNAT rule")
	}
	plan, err = PlanFromSiteWithUpstream(site, UpstreamObservation{Interface: "wan0", MAC: plan.Interfaces[0].MAC, Address: "192.168.4.3/24", Gateway: "192.168.4.1"})
	if err != nil {
		t.Fatal(err)
	}
	ruleset, err := RenderNFT(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`iifname "wan0" oifname "infra0" ip saddr 192.168.4.0/24 ip daddr 10.10.10.10/32 tcp dport 53 counter accept`,
		`iifname "wan0" oifname "infra0" ip saddr 192.168.4.0/24 ip daddr 10.10.10.10/32 udp dport 53 counter accept`,
		`iifname "wan0" ip saddr 192.168.4.0/24 ip daddr 192.168.4.3 tcp dport 53 dnat to 10.10.10.10:53`,
		`iifname "wan0" ip saddr 192.168.4.0/24 ip daddr 192.168.4.3 udp dport 53 dnat to 10.10.10.10:53`,
	} {
		if !strings.Contains(ruleset, expected) {
			t.Fatalf("published DNS policy missing %q:\n%s", expected, ruleset)
		}
	}
	if strings.Contains(ruleset, "192.168.4.0/24 masquerade") || strings.Contains(ruleset, "publish-dns-any") {
		t.Fatal("published DNS policy introduced an upstream SNAT or arbitrary rule")
	}
}

func TestUpstreamObservationRejectsInternalOverlapAndWrongMAC(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	for name, observation := range map[string]UpstreamObservation{
		"internal overlap": {Interface: "wan0", MAC: plan.Interfaces[0].MAC, Address: "10.10.10.3/24", Gateway: "10.10.10.1"},
		"wrong MAC":        {Interface: "wan0", MAC: "02:00:00:00:01:02", Address: "192.168.4.3/24", Gateway: "192.168.4.1"},
	} {
		if err := ValidateUpstreamObservation(plan, observation); err == nil {
			t.Fatalf("%s observation was accepted", name)
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

func TestManagedGatewayAllowsDiagnosticICMPEchoFromInternalZones(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	ruleset, err := RenderNFT(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateNFT(ruleset); err != nil {
		t.Fatalf("rendered ruleset is invalid: %v", err)
	}
	want := "iifname { \"infra0\", \"trusted0\", \"servers0\", \"sandbox0\", \"mgmt0\" } ip protocol icmp icmp type echo-request counter accept comment \"boetticher:allow:input-diagnostic-icmp\""
	if !strings.Contains(ruleset, want) {
		t.Fatalf("managed firewall does not permit diagnostic ICMP echo requests from internal zones:\n%s", ruleset)
	}
	if strings.Contains(ruleset, "iifname \"wan0\" ip protocol icmp") {
		t.Fatal("managed firewall permits WAN-sourced ICMP input")
	}
	if strings.Contains(ruleset, "iifname \"sandbox0\" oifname \"trusted0\" ip protocol icmp") {
		t.Fatal("managed firewall added an inter-zone ICMP allow")
	}
}

func TestComposedModuleIntentsAreNarrowManagedAllows(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	tailnetEnabled, bifrostEnabled := true, true
	config.Modules.TailnetRouter = &model.ToggleModuleConfig{Enabled: &tailnetEnabled}
	config.Modules.Bifrost = &model.BifrostModuleConfig{
		Enabled:   &bifrostEnabled,
		Upstreams: []model.BifrostUpstreamConfig{{Name: "openrouter", BaseURL: "https://openrouter.ai/api/v1", APIKeySecret: "openrouter_api_key"}},
		Models:    []model.BifrostModelConfig{{Alias: "selected-alias", Upstream: "openrouter", Model: "selected/openrouter-model"}},
	}
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	ruleset, err := renderNFTWithResolver(plan, func(host string) ([]net.IP, error) {
		if host == "openrouter.ai" {
			return []net.IP{net.ParseIP("198.51.100.11"), net.ParseIP("198.51.100.10")}, nil
		}
		if host == "controlplane.tailscale.com" {
			return []net.IP{net.ParseIP("198.51.100.30")}, nil
		}
		if strings.HasPrefix(host, "derp") && strings.HasSuffix(host, "-all.tailscale.com") {
			return []net.IP{net.ParseIP("198.51.100.31")}, nil
		}
		return nil, fmt.Errorf("unexpected endpoint %s", host)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"10.10.5.10/32 ip daddr 10.10.20.60/32 tcp dport 443",
		"10.10.5.10/32 ip daddr 10.10.10.20/32 tcp dport 443",
		"10.10.10.20/32 ip daddr 10.10.99.5/32 tcp dport 8006",
		"10.10.99.5/32 ip daddr 10.10.5.10/32 tcp dport 22",
		"set boetticher_endpoint_29 { type ipv4_addr; elements = { 198.51.100.10, 198.51.100.11 } }",
		"10.10.20.60/32 ip daddr @boetticher_endpoint_29 tcp dport 443",
		"oifname \"wan0\" ip saddr 10.10.5.10/32 masquerade comment \"boetticher:nat-transit\"",
		"set module_guest_sources { type ipv4_addr; elements = {",
		"10.10.10.20, 10.10.20.60, 10.10.5.10",
		"iifname \"servers0\" ip saddr != @module_guest_sources oifname \"wan0\"",
		"arbitrary-egress",
	} {
		if !strings.Contains(ruleset, expected) {
			t.Errorf("managed module policy missing %q:\n%s", expected, ruleset)
		}
	}
	if strings.Index(ruleset, "10.10.5.10/32 ip daddr 10.10.20.60/32") > strings.Index(ruleset, "TRANSIT-SERVERS-DROP") {
		t.Fatal("narrow tailnet-to-Bifrost allow occurs after the TRANSIT default deny")
	}
	if strings.Contains(ruleset, `iifname "transit0" ip daddr @servers_net accept`) {
		t.Fatal("managed module policy contains a broad TRANSIT-to-SERVERS allow")
	}
	if strings.Index(ruleset, "10.10.99.5/32 ip daddr 10.10.5.10/32 tcp dport 22") > strings.Index(ruleset, "TO-TRANSIT-DROP") {
		t.Fatal("narrow Proxmox jump path occurs after the TRANSIT default deny")
	}
	if strings.Contains(ruleset, "10051") {
		t.Fatal("Pulse-based monitoring policy retains the removed Zabbix port")
	}
	if strings.Contains(ruleset, `iifname "servers0" oifname "wan0" ip saddr @servers_net tcp dport { 53, 80, 443, 853 } counter accept`) {
		t.Fatal("module-owned SERVERS guests inherit the unrestricted zone Internet allow")
	}
}

func TestDistinctBifrostUpstreamsHaveDistinctSemanticCounterIDs(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	bifrostEnabled := true
	config.Modules.Bifrost = &model.BifrostModuleConfig{
		Enabled: &bifrostEnabled,
		Upstreams: []model.BifrostUpstreamConfig{
			{Name: "openrouter", BaseURL: "https://openrouter.ai/api/v1", APIKeySecret: "openrouter_api_key"},
			{Name: "anthropic", BaseURL: "https://api.anthropic.com/v1", APIKeySecret: "anthropic_api_key"},
		},
		Models: []model.BifrostModelConfig{
			{Alias: "openrouter-model", Upstream: "openrouter", Model: "openrouter/model"},
			{Alias: "anthropic-model", Upstream: "anthropic", Model: "anthropic/model"},
		},
	}
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	ruleset, err := renderNFTWithResolver(plan, func(host string) ([]net.IP, error) {
		if host == "openrouter.ai" {
			return []net.IP{net.ParseIP("198.51.100.10")}, nil
		}
		if host == "api.anthropic.com" {
			return []net.IP{net.ParseIP("198.51.100.20")}, nil
		}
		return nil, fmt.Errorf("unexpected endpoint %s", host)
	})
	if err != nil {
		t.Fatal(err)
	}
	var upstreamRules []string
	for _, line := range strings.Split(ruleset, "\n") {
		if strings.Contains(line, "boetticher:allow:module-module_bifrost_configured_bifrost_upstream_https_access_") {
			upstreamRules = append(upstreamRules, line)
		}
	}
	if len(upstreamRules) != 2 || upstreamRules[0] == upstreamRules[1] {
		t.Fatalf("Bifrost upstream semantic counter rules = %v", upstreamRules)
	}
}

func TestEndpointResolutionFailsClosed(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	bifrostEnabled := true
	config.Modules.Bifrost = &model.BifrostModuleConfig{
		Enabled:   &bifrostEnabled,
		Upstreams: []model.BifrostUpstreamConfig{{Name: "openrouter", BaseURL: "https://openrouter.ai/api/v1", APIKeySecret: "openrouter_api_key"}},
		Models:    []model.BifrostModelConfig{{Alias: "selected-alias", Upstream: "openrouter", Model: "selected/openrouter-model"}},
	}
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	_, err = renderNFTWithResolver(plan, func(string) ([]net.IP, error) {
		return nil, errors.New("temporary resolver failure")
	})
	if err == nil || !strings.Contains(err.Error(), "HOLD: resolve endpoint openrouter.ai") {
		t.Fatalf("endpoint resolver failure was not preserved as a HOLD: %v", err)
	}
}

func TestEndpointResolutionRejectsPrivateAddress(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("private-endpoint", "age1privateendpoint", model.GatewayModeManaged))
	enabled := true
	config.Modules.Bifrost = &model.BifrostModuleConfig{
		Enabled:   &enabled,
		Upstreams: []model.BifrostUpstreamConfig{{Name: "provider", BaseURL: "https://provider.example/v1", APIKeySecret: "provider_api_key"}},
		Models:    []model.BifrostModelConfig{{Alias: "selected", Upstream: "provider", Model: "provider/model"}},
	}
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	_, err = renderNFTWithResolver(plan, func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.10.20.1")}, nil
	})
	if err == nil || !strings.Contains(err.Error(), "non-public IPv4") {
		t.Fatalf("private endpoint address was accepted: %v", err)
	}
}

func TestQualifiedModuleLoggingIntentResolvesCollector(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	enabled := true
	config.Modules.Logging = &model.ToggleModuleConfig{Enabled: &enabled}
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	rule := policyRuleForIntent(site, "logging", model.NetworkIntent{
		Source: "lab-monitor-01", Destination: "logs.lab.home.arpa", Protocol: "tcp", Ports: []string{"19532"}, Purpose: "native journal upload",
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
	tailnetEnabled, bifrostEnabled := true, true
	config.Modules.TailnetRouter = &model.ToggleModuleConfig{Enabled: &tailnetEnabled}
	config.Modules.Bifrost = &model.BifrostModuleConfig{
		Enabled:   &bifrostEnabled,
		Upstreams: []model.BifrostUpstreamConfig{{Name: "openrouter", BaseURL: "https://openrouter.ai/api/v1", APIKeySecret: "openrouter_api_key"}},
		Models:    []model.BifrostModelConfig{{Alias: "selected-alias", Upstream: "openrouter", Model: "selected/openrouter-model"}},
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
	firewallDisabled, tailnetEnabled, bifrostEnabled := false, true, true
	config.Modules.Firewall = &model.ToggleModuleConfig{Enabled: &firewallDisabled}
	config.Modules.TailnetRouter = &model.ToggleModuleConfig{Enabled: &tailnetEnabled}
	config.Modules.Bifrost = &model.BifrostModuleConfig{
		Enabled:   &bifrostEnabled,
		Upstreams: []model.BifrostUpstreamConfig{{Name: "openrouter", BaseURL: "https://openrouter.ai/api/v1", APIKeySecret: "openrouter_api_key"}},
		Models:    []model.BifrostModelConfig{{Alias: "selected-alias", Upstream: "openrouter", Model: "selected/openrouter-model"}},
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
	for _, expected := range []string{"10.10.0.0/16", "10.10.5.10", "10.10.5.0/24", "10.10.5.1", "subnet-route", "route approval", "accept-dns=false", "Bifrost HTTPS", "monitoring HTTPS", "openrouter.ai", "required return routing", "Proxmox API", "SSH", "enforcement is NOT ACTIVE", "operator implementation responsibility"} {
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

func TestPulseHTTPSIsAllowedFromModeledClientZones(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	ruleset, err := RenderNFT(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"iifname \"transit0\" oifname \"infra0\" ip saddr 10.10.5.0/24 ip daddr 10.10.10.20/32 tcp dport 443 counter accept",
		"iifname \"servers0\" oifname \"infra0\" ip saddr 10.10.20.0/24 ip daddr 10.10.10.20/32 tcp dport 443 counter accept",
		"iifname \"trusted0\" oifname \"infra0\" ip saddr 10.10.30.0/24 ip daddr 10.10.10.20/32 tcp dport 443 counter accept",
	} {
		if !strings.Contains(ruleset, expected) {
			t.Errorf("Pulse client-zone rule missing %q:\\n%s", expected, ruleset)
		}
	}
	if strings.Contains(ruleset, "iifname \"trusted0\" oifname \"infra0\" ip saddr 10.10.30.0/24 ip daddr @infra_net tcp dport 443 counter accept") {
		t.Fatal("TRUSTED retains a broad HTTPS-to-INFRA rule")
	}
	if strings.Index(ruleset, "iifname \"transit0\" oifname \"infra0\" ip saddr 10.10.5.0/24") > strings.Index(ruleset, "TRANSIT-INFRA-DROP") {
		t.Fatal("TRANSIT-to-Pulse allow occurs after the TRANSIT default deny")
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

func TestTailnetRouterUsesTheSingleDNSAndNTPService(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	enabled := true
	config.Modules.TailnetRouter = &model.ToggleModuleConfig{Enabled: &enabled}
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	rules := policyRules(site)
	seen := map[string]map[string]bool{"Tailscale router DNS resolution": {}, "Tailscale router time synchronisation": {}}
	for _, rule := range rules {
		for purpose := range seen {
			if strings.Contains(rule.Description, purpose) {
				seen[purpose][rule.DestinationCIDR] = true
			}
		}
	}
	for purpose, destinations := range seen {
		if len(destinations) != 1 || !destinations["10.10.10.10/32"] {
			t.Fatalf("Tailnet %s destinations = %v, want the single DNS endpoint", purpose, destinations)
		}
	}
}

func TestLogicalDNSIntentExpandsToAllManagedDNSEndpoints(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	rules := policyRulesForIntent(site, "monitoring", model.NetworkIntent{
		Source: "lab-monitor-01", Destination: "dns", Protocol: "tcp/udp", Ports: []string{"53"}, Purpose: "DNS resolution",
	})
	seen := map[string]bool{}
	names := map[string]bool{}
	for _, rule := range rules {
		seen[rule.DestinationCIDR] = true
		names[rule.Name] = true
	}
	if len(seen) != 1 || len(names) != 1 || !seen["10.10.10.10/32"] {
		t.Fatalf("logical DNS intent destinations = %v, names = %v, want the managed DNS endpoint", seen, names)
	}
}

func TestDeclaredEndpointsReachOnlyTheSmallstepCADestination(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	rules := policyRules(site)
	foundMonitor := false
	for _, rule := range rules {
		if strings.Contains(rule.Name, "HTTPS to Smallstep CA") {
			if rule.Name == "lab-monitor-01 HTTPS to Smallstep CA" {
				foundMonitor = true
				if rule.SourceCIDR != "10.10.10.20/32" || rule.DestinationCIDR != "10.10.10.10/32" || !reflect.DeepEqual(rule.Ports, []string{StepCAPort}) {
					t.Fatalf("Smallstep monitor rule = %#v", rule)
				}
			}
			if rule.Name == "lab-proxmox-01 HTTPS to Smallstep CA" || rule.SourceCIDR == "10.10.0.0/16" {
				t.Fatalf("Smallstep CA rule is broader than a declared endpoint: %#v", rule)
			}
		}
	}
	if !foundMonitor {
		t.Fatal("default monitoring endpoint has no Smallstep CA rule")
	}
}

func TestAirVPNSelectedSourcesUseTransitWithoutDirectWANFallback(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("airvpn", "age1airvpn", model.GatewayModeManaged))
	airvpnEnabled, bifrostEnabled := true, true
	config.Modules.AirVPN = &model.AirVPNModuleConfig{Enabled: &airvpnEnabled, Servers: "europe"}
	config.Modules.Bifrost = &model.BifrostModuleConfig{
		Enabled: &bifrostEnabled, Network: model.ModuleNetworkAirVPN,
		Upstreams: []model.BifrostUpstreamConfig{{Name: "provider", BaseURL: "https://provider.example/v1", APIKeySecret: "provider_api_key"}},
		Models:    []model.BifrostModelConfig{{Alias: "selected", Upstream: "provider", Model: "provider/model"}},
	}
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	profile := AirVPNProfile{EndpointHost: "airvpn.example", EndpointPort: 1637, TunnelAddress: "10.64.12.3", SHA256: strings.Repeat("a", 64)}
	plan, err := PlanFromSiteWithAirVPN(site, profile)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan.AirVPNSources, []string{"10.10.20.60/32"}) || len(plan.PolicyRoutes) != 1 {
		t.Fatalf("unexpected AirVPN source policy: sources=%v routes=%v", plan.AirVPNSources, plan.PolicyRoutes)
	}
	route := plan.PolicyRoutes[0]
	if route.SourceCIDR != "10.10.20.60/32" || route.Table != 51820 || route.Priority != 10000 || route.DefaultGateway != model.AirVPNGuestAddress || route.DefaultInterface != "transit0" || len(route.InternalRoutes) != 6 {
		t.Fatalf("unexpected AirVPN policy route: %#v", route)
	}
	var selectedRule PolicyRule
	for _, rule := range plan.Rules {
		if rule.Route == "airvpn" {
			selectedRule = rule
			break
		}
	}
	if selectedRule.From != "SERVERS" || selectedRule.To != "TRANSIT" || selectedRule.SourceCIDR != "10.10.20.60/32" || selectedRule.SourceMAC != networkmodel.ManagedModuleMAC(210) || selectedRule.NAT {
		t.Fatalf("selected-source transit rule is incomplete: %#v", selectedRule)
	}
	plan, err = BindAirVPNEndpoint(plan, func(host string) ([]net.IP, error) {
		if host == "airvpn.example" || host == "provider.example" {
			return []net.IP{net.ParseIP("198.51.100.44")}, nil
		}
		return nil, fmt.Errorf("unexpected endpoint %s", host)
	})
	if err != nil {
		t.Fatal(err)
	}
	ruleset, err := RenderNFTWithResolver(plan, func(host string) ([]net.IP, error) {
		if host == "airvpn.example" || host == "provider.example" {
			return []net.IP{net.ParseIP("198.51.100.44")}, nil
		}
		return nil, fmt.Errorf("unexpected endpoint %s", host)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`ip saddr @airvpn_sources oifname "wan0" counter log prefix "boetticher AIRVPN-DIRECT-DROP " drop`,
		`iifname "servers0" ether saddr 02:00:00:03:00:d2 oifname "transit0" ip saddr 10.10.20.60/32 ip daddr @boetticher_endpoint_1 tcp dport 443 counter accept`,
		"oifname \"wan0\" ip saddr != @airvpn_sources ip saddr 10.10.20.0/24 masquerade comment \"boetticher:nat-servers\"",
		"oifname \"wan0\" ip saddr 10.10.5.20/32 ip daddr @boetticher_endpoint_0 udp dport 1637 masquerade comment \"boetticher:nat-airvpn-handshake\"",
		`iifname "transit0" oifname "wan0" counter log prefix "boetticher TRANSIT-INTERNET-DROP " drop`,
	} {
		if !strings.Contains(ruleset, expected) {
			t.Errorf("AirVPN ruleset is missing %q:\n%s", expected, ruleset)
		}
	}
	if strings.Contains(ruleset, `oifname "transit0" ip saddr @airvpn_sources counter accept comment "boetticher:allow:airvpn-selected-transit"`) {
		t.Fatal("AirVPN selected source has a source-wide transit allow")
	}
	if strings.Contains(ruleset, `oifname "wan0" ip saddr 10.10.20.60/32 masquerade`) {
		t.Fatal("selected AirVPN source has a direct WAN NAT rule")
	}
}

func TestArrAirVPNEgressIsBoundedAndFailClosed(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("arr-airvpn", "age1arr", model.GatewayModeManaged))
	enabled := true
	config.Modules.AirVPN = &model.AirVPNModuleConfig{Enabled: &enabled, Servers: "australia"}
	config.Modules.Arr = &model.ArrModuleConfig{Enabled: &enabled, Network: model.ModuleNetworkAirVPN}
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	profile := AirVPNProfile{EndpointHost: "airvpn.example", EndpointPort: 1637, TunnelAddress: "10.64.12.3", SHA256: strings.Repeat("a", 64)}
	plan, err := PlanFromSiteWithAirVPN(site, profile)
	if err != nil {
		t.Fatal(err)
	}
	var egress PolicyRule
	for _, rule := range plan.Rules {
		if rule.Name == "ARR media acquisition through AirVPN" {
			egress = rule
			break
		}
	}
	if egress.From != "SERVERS" || egress.To != "TRANSIT" || egress.Action != "allow" || egress.Protocol != "any" || egress.SourceCIDR != model.ArrGuestAddress+"/32" || egress.SourceMAC != model.ArrGuestMAC || egress.DestinationCIDR != model.AirVPNGuestAddress+"/32" || egress.NAT || egress.Route != "airvpn" {
		t.Fatalf("ARR AirVPN egress rule = %#v", egress)
	}
	if !reflect.DeepEqual(plan.AirVPNSources, []string{model.ArrGuestAddress + "/32"}) {
		t.Fatalf("ARR AirVPN source set = %#v", plan.AirVPNSources)
	}
	plan, err = BindAirVPNEndpoint(plan, func(host string) ([]net.IP, error) {
		if host == "airvpn.example" {
			return []net.IP{net.ParseIP("198.51.100.44")}, nil
		}
		return nil, fmt.Errorf("unexpected endpoint %s", host)
	})
	if err != nil {
		t.Fatal(err)
	}
	ruleset, err := RenderNFTWithResolver(plan, func(host string) ([]net.IP, error) {
		if host == "airvpn.example" {
			return []net.IP{net.ParseIP("198.51.100.44")}, nil
		}
		return nil, fmt.Errorf("unexpected endpoint %s", host)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`iifname "servers0" ether saddr 02:00:00:00:02:10 oifname "transit0" ip saddr 10.10.20.110/32 ip daddr 10.10.5.20/32 counter accept`,
		`iifname "servers0" ether saddr 02:00:00:00:02:10 ip saddr != 10.10.20.110/32 counter log prefix "boetticher AIRVPN-SOURCE-MISMATCH-DROP " drop`,
		`ip saddr @airvpn_sources oifname "wan0" counter log prefix "boetticher AIRVPN-DIRECT-DROP " drop`,
		`oifname "wan0" ip saddr != @airvpn_sources ip saddr 10.10.20.0/24 masquerade comment "boetticher:nat-servers"`,
	} {
		if !strings.Contains(ruleset, want) {
			t.Errorf("ARR AirVPN ruleset is missing %q:\n%s", want, ruleset)
		}
	}
	if strings.Contains(ruleset, `oifname "wan0" ip saddr 10.10.20.110/32 masquerade`) {
		t.Fatal("ARR AirVPN source has a direct WAN NAT rule")
	}
	if strings.Contains(ruleset, `ether saddr 02:00:00:00:02:10 oifname "transit0" ip saddr 10.10.20.110/32 ip daddr 0.0.0.0/0`) {
		t.Fatal("ARR AirVPN rule still permits every TRANSIT destination")
	}
}

func TestAirVPNModuleIntentCarriesStableSourceMAC(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	site.ModuleConfig = map[string]model.ModuleConfig{"bifrost": {Network: model.ModuleNetworkAirVPN}}
	component := model.Component{Name: "lab-bifrost-01", VMID: 210, Module: "bifrost", Address: "10.10.20.60"}
	if got, want := componentSourceMAC(site, component), networkmodel.ManagedModuleMAC(210); got != want {
		t.Fatalf("AirVPN module source MAC = %q, want %q", got, want)
	}
}

func TestRenderRejectsInvalidSourceMAC(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	plan.Rules = []PolicyRule{{
		Name: "invalid-source-mac", From: "SERVERS", To: "TRANSIT", Action: "allow", Protocol: "any",
		SourceCIDR: "10.10.20.110/32", DestinationCIDR: "0.0.0.0/0", SourceMAC: "not-a-mac",
	}}
	if _, err := RenderNFT(plan); err == nil || !strings.Contains(err.Error(), "invalid source MAC") {
		t.Fatalf("invalid source MAC was rendered: %v", err)
	}
}
