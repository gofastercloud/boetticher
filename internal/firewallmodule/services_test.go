package firewallmodule

import (
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/openwrt"
	"github.com/gofastercloud/boetticher/internal/tailnet"
)

func TestObservabilityDNSSectionsUseOwnedPublicNamesAndMonitorAddress(t *testing.T) {
	sections := observabilityDNSSections("example.com")
	if len(sections) != 4 {
		t.Fatalf("observability DNS section count = %d", len(sections))
	}
	for _, name := range []string{"observability.example.com", "status.example.com", "ingest.example.com", "metrics.example.com"} {
		found := false
		for _, section := range sections {
			if section.Options["name"] == name && section.Options["ip"] == "10.10.10.20" && strings.HasPrefix(section.Name, "boetticher_observability_record_") {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing owned observability DNS record %s: %#v", name, sections)
		}
	}
	foreign := sections[0]
	foreign.Options = map[string]string{"name": foreign.Options["name"], "ip": "10.10.10.99"}
	if _, err := DiffOwned(map[string]openwrt.UCISection{foreign.Name: {Type: foreign.Type, Options: foreign.Options}}, sections); err == nil {
		t.Fatal("conflicting observability DNS record was accepted")
	}
}

func TestRegisteredSystemFirewallRulesAreOwnedAndPruned(t *testing.T) {
	current := map[string]openwrt.UCISection{
		"boetticher_system_print-server_trusted": {Type: "rule", Options: map[string]string{"name": "Boetticher system print-server trusted", "src": "trusted", "dest": "servers", "dest_ip": "10.10.20.61", "proto": "tcp", "dest_port": "631", "family": "ipv4", "target": "ACCEPT"}},
		"user_rule":                              {Type: "rule", Options: map[string]string{"name": "user rule", "src": "trusted", "dest": "servers", "dest_ip": "10.10.20.62", "proto": "tcp", "dest_port": "8080", "family": "ipv4", "target": "ACCEPT"}},
	}
	changes, err := DiffFirewall(current, nil)
	if err != nil {
		t.Fatal(err)
	}
	foundDelete := false
	for _, change := range changes {
		if change.Kind == MutationDelete && change.Section.Name == "boetticher_system_print-server_trusted" {
			foundDelete = true
		}
		if change.Section.Name == "user_rule" {
			t.Fatal("unowned user firewall rule was selected")
		}
	}
	if !foundDelete {
		t.Fatal("owned registered-system rule was not pruned")
	}
}

func TestServiceStateComposesSharedDHCPDNSAndTimeOwnership(t *testing.T) {
	site := model.NewSite("lab", "controller-local", model.GatewayModeManaged)
	enabled := true
	state, err := ServiceStateFromModules(site, clientservices.Modules{
		DNS:  &clientservices.DNSConfig{Enabled: &enabled, Records: []clientservices.DNSRecord{{Name: "app", Type: "A", Value: "10.10.30.61"}}},
		DHCP: &clientservices.DHCPConfig{Enabled: &enabled, Reservations: []clientservices.Reservation{{Name: "client", Zone: "TRUSTED", MAC: "02:00:00:00:30:61", Address: "10.10.30.61"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := sectionNames(state.DHCP)
	for _, name := range []string{"boetticher_dnsmasq", "boetticher_dhcp_trusted", "boetticher_host_client", "boetticher_record_napp"} {
		if !strings.Contains(joined, name) {
			t.Fatalf("shared DHCP/DNS scope omitted %s: %s", name, joined)
		}
	}
	for _, section := range state.DHCP {
		if strings.HasPrefix(section.Name, "boetticher_dhcp_") && section.Name != "boetticher_dhcp_sandbox" && section.Name != "boetticher_dhcp_servers" && section.Name != "boetticher_dhcp_trusted" {
			if section.Options["start"] != "2" || section.Options["limit"] != "253" || section.Options["dynamicdhcp"] != "0" {
				t.Fatalf("reservation-only scope has no valid static-only range: %#v", section)
			}
		}
		if strings.HasPrefix(section.Name, "boetticher_dhcp_") {
			gateway := ""
			for _, option := range section.Lists["dhcp_option"] {
				if strings.HasPrefix(option, "3,") {
					gateway = strings.TrimPrefix(option, "3,")
				}
			}
			if gateway == "" {
				t.Fatalf("%s omitted the legacy default gateway option: %#v", section.Name, section.Lists["dhcp_option"])
			}
			foundRoute := false
			for _, option := range section.Lists["dhcp_option"] {
				if option == "121,10.10.0.0/16,"+gateway+",0.0.0.0/0,"+gateway {
					foundRoute = true
				}
			}
			if !foundRoute {
				t.Fatalf("%s did not advertise LAB aggregate and default route: %#v", section.Name, section.Lists["dhcp_option"])
			}
		}
		if section.Name == "boetticher_dhcp_sandbox" && (section.Options["networkid"] != "boetticher_sandbox" || len(section.Lists["tag"]) != 0) {
			t.Fatalf("sandbox suppression did not preserve a usable tagged range: %#v", section)
		}
	}
	if len(state.Stubby) != 3 || len(state.System) != 1 {
		t.Fatalf("unexpected supporting service sections: stubby=%#v system=%#v", state.Stubby, state.System)
	}
	if !strings.Contains(sectionNames(state.Firewall), "external_dns") || !strings.Contains(sectionNames(state.Firewall), "_ntp") {
		t.Fatalf("service-specific firewall policy was not composed: %s", sectionNames(state.Firewall))
	}
}

func TestObservabilityFirewallProjectionUsesPersistedRoleBindings(t *testing.T) {
	site := model.NewSite("lab", "controller-local", model.GatewayModeManaged)
	enabled := true
	modules := clientservices.Modules{Observability: &clientservices.ObservabilityConfig{
		Enabled:    &enabled,
		Collection: clientservices.ObservabilityCollectionBindings{Controller: "10.10.20.10", ProxmoxHost: "10.10.99.5", Runtime: "10.10.10.20"},
	}}
	state, err := ServiceStateFromModules(site, modules)
	if err != nil {
		t.Fatal(err)
	}
	find := func(name string) Section {
		for _, section := range state.Firewall {
			if section.Name == name {
				return section
			}
		}
		t.Fatalf("missing firewall section %s", name)
		return Section{}
	}
	rule := find(observabilityControllerExporterRule)
	if rule.Options["src"] != "infra" || rule.Options["src_ip"] != "10.10.10.20/32" || rule.Options["dest"] != "servers" || rule.Options["dest_ip"] != "10.10.20.10/32" || rule.Options["dest_port"] != "9100" {
		t.Fatalf("controller exporter rule is not exact: %#v", rule.Options)
	}
	trusted := find(observabilityTrustedIngressRule)
	if trusted.Options["src"] != "trusted" || trusted.Options["src_ip"] != "10.10.30.0/24" || trusted.Options["dest_ip"] != "10.10.10.20/32" || trusted.Options["dest_port"] != "443" {
		t.Fatalf("trusted observability rule is not exact: %#v", trusted.Options)
	}
}

func TestObservabilityFirewallProjectionTailnetRequiresExactReservation(t *testing.T) {
	site := model.NewSite("lab", "controller-local", model.GatewayModeManaged)
	enabled := true
	modules := clientservices.Modules{Tailnet: &clientservices.TailnetConfig{Enabled: true}, Observability: &clientservices.ObservabilityConfig{Enabled: &enabled, Collection: clientservices.ObservabilityCollectionBindings{Controller: "10.10.20.10", ProxmoxHost: "10.10.99.5", Runtime: "10.10.10.20"}}, DNS: &clientservices.DNSConfig{Enabled: &enabled}, DHCP: &clientservices.DHCPConfig{Enabled: &enabled, Reservations: []clientservices.Reservation{{Name: tailnet.GuestName, Zone: "TRANSIT", MAC: "02:00:00:00:05:11", Address: tailnet.GuestAddress}}}}
	state, err := ServiceStateFromModules(site, modules)
	if err != nil {
		t.Fatal(err)
	}
	for _, section := range state.Firewall {
		if section.Name == observabilityTailnetIngressRule {
			t.Fatal("spoofed Tailnet MAC produced observability rule")
		}
	}
	modules.DHCP.Reservations[0].MAC = tailnet.GuestMAC
	state, err = ServiceStateFromModules(site, modules)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, section := range state.Firewall {
		if section.Name == observabilityTailnetIngressRule {
			found = true
			if section.Options["src_mac"] != tailnet.GuestMAC || section.Options["dest_ip"] != "10.10.10.20/32" || section.Options["dest_port"] != "443" {
				t.Fatalf("Tailnet observability rule is not exact: %#v", section.Options)
			}
		}
	}
	if !found {
		t.Fatal("exact Tailnet reservation did not produce observability rule")
	}
}

func TestObservabilityFirewallProjectionDisabledAndCleanupScoped(t *testing.T) {
	site := model.NewSite("lab", "controller-local", model.GatewayModeManaged)
	disabled := false
	state, err := ServiceStateFromModules(site, clientservices.Modules{Observability: &clientservices.ObservabilityConfig{Enabled: &disabled}})
	if err != nil || len(state.Firewall) != 0 {
		t.Fatalf("disabled observability projected firewall rules: %#v %v", state.Firewall, err)
	}
	name := observabilityRuntimeIngressRule
	current := map[string]openwrt.UCISection{name: {Type: "rule", Options: map[string]string{"name": "old"}}}
	if _, ok := FirewallScope(current, nil)[name]; !ok {
		t.Fatal("observability rule was not retained for exact cleanup")
	}
}

func TestServiceStateKeepsUpstreamTimeWhenClientDHCPIsDisabled(t *testing.T) {
	site := model.NewSite("lab", "controller-local", model.GatewayModeManaged)
	disabled := false
	state, err := ServiceStateFromModules(site, clientservices.Modules{DHCP: &clientservices.DHCPConfig{Enabled: &disabled, Time: clientservices.TimeConfig{Upstreams: []string{"162.159.200.1"}, Serve: boolPtr(false)}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(state.System) != 1 || state.System[0].Options["enable_server"] != "0" {
		t.Fatalf("client-facing NTP was not disabled while upstream time remained: %#v", state.System)
	}
	if len(state.DHCP) != 2 || state.DHCP[1].Name != "boetticher_home" || len(state.Firewall) != 0 {
		t.Fatalf("disabled DHCP unexpectedly retained client-facing sections: %#v", state)
	}
}

func TestServiceStateDeniesPublicResolverAndTimePortsViaVPN(t *testing.T) {
	site := model.NewSite("lab", "controller-local", model.GatewayModeManaged)
	enabled := true
	state, err := ServiceStateFromModules(site, clientservices.Modules{
		DNS:  &clientservices.DNSConfig{Enabled: &enabled},
		DHCP: &clientservices.DHCPConfig{Enabled: &enabled},
		VPN:  &clientservices.VPNConfig{Enabled: &enabled, Location: "europe"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"boetticher_deny_trusted_external_dns_udp_vpn": false,
		"boetticher_deny_trusted_external_dns_tcp_vpn": false,
		"boetticher_deny_trusted_external_dot_tcp_vpn": false,
		"boetticher_deny_trusted_external_ntp_vpn":     false,
	}
	for _, section := range state.Firewall {
		if _, ok := want[section.Name]; ok && section.Options["dest"] == "vpn" {
			want[section.Name] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("missing VPN service deny rule %s", name)
		}
	}
}

func TestNativeRecordSuffixKeepsHyphenAndDotIdentitiesDistinct(t *testing.T) {
	if nativeRecordSuffix("app-a.lab.home.arpa") == nativeRecordSuffix("app.a-lab.home.arpa") {
		t.Fatal("distinct DNS identities mapped to the same native section name")
	}
}

func TestNativeHostSectionNamesAcceptDNSHyphensWithoutCollisions(t *testing.T) {
	left := nativeHostSectionName("client-one")
	right := nativeHostSectionName("client_hone")
	if strings.Contains(left, "-") || left == right {
		t.Fatalf("host identities were not safely encoded: %q and %q", left, right)
	}
}

func TestInfrastructureDNSHasOnePTROwnerPerAddressAndStableAliases(t *testing.T) {
	site := model.NewSite("lab", "controller-local", model.GatewayModeManaged)
	site.Components[0].DNSAliases = []string{"pve"}
	sections, err := bindingDNSSections(site)
	if err != nil {
		t.Fatal(err)
	}
	hostrecords, cnames := 0, 0
	for _, section := range sections {
		switch section.Type {
		case "hostrecord":
			hostrecords++
		case "cname":
			cnames++
		}
	}
	if hostrecords != len(site.Components)+len(site.Network.Zones)+1 || cnames != 1 {
		t.Fatalf("unexpected infrastructure DNS projection: hostrecords=%d cnames=%d", hostrecords, cnames)
	}
}

func TestInfrastructureDNSRejectsNameCollision(t *testing.T) {
	site := model.NewSite("lab", "controller-local", model.GatewayModeManaged)
	site.Components = append(site.Components, model.Component{Hostname: "servers-gateway", Address: "10.10.99.8"})
	if _, err := InfrastructureDNSRecords(site); err == nil {
		t.Fatal("conflicting infrastructure DNS name was accepted")
	}
}

func TestServiceStateRejectsUserAThatWouldCreateSecondPTR(t *testing.T) {
	site := model.NewSite("lab", "controller-local", model.GatewayModeManaged)
	enabled := true
	state, err := InfrastructureDNSRecords(site)
	if err != nil {
		t.Fatal(err)
	}
	persisted := make([]clientservices.DNSRecord, 0, len(state))
	for _, record := range state {
		persisted = append(persisted, clientservices.DNSRecord{Name: record.Name, Type: record.Type, Value: record.Address})
	}
	_, err = ServiceStateFromModules(site, clientservices.Modules{DNS: &clientservices.DNSConfig{
		Enabled: &enabled, Infrastructure: persisted,
		Records: []clientservices.DNSRecord{{Name: "same-address", Type: "A", Value: site.Components[0].Address}},
	}})
	if err == nil || !strings.Contains(err.Error(), "use a CNAME alias") {
		t.Fatalf("same-address user A was not refused clearly: %v", err)
	}
}

func TestInfrastructureAddressChangeRemovesOnlyOwnedRecord(t *testing.T) {
	site := model.NewSite("lab", "controller-local", model.GatewayModeManaged)
	want, err := bindingDNSSections(site)
	if err != nil {
		t.Fatal(err)
	}
	old := want[0]
	current := map[string]openwrt.UCISection{
		old.Name:  {Type: old.Type, Options: old.Options, Lists: old.Lists},
		"foreign": {Type: "hostrecord", Options: map[string]string{"name": "foreign." + site.Network.Domain, "ip": old.Options["ip"]}},
	}
	site.Components[0].Address = "10.10.99.8"
	updated, err := bindingDNSSections(site)
	if err != nil {
		t.Fatal(err)
	}
	mutations, err := DiffOwned(current, updated)
	if err != nil {
		t.Fatal(err)
	}
	deletedOld, keptForeign := false, false
	for _, mutation := range mutations {
		if mutation.Kind == MutationDelete && mutation.Section.Name == old.Name {
			deletedOld = true
		}
		if mutation.Section.Name == "foreign" {
			keptForeign = true
		}
	}
	if !deletedOld || keptForeign {
		t.Fatalf("address change cleanup was not exact: %#v", mutations)
	}
}

func TestServiceStateUsesNativeGlobalSectionsAndDisablesServing(t *testing.T) {
	site := model.NewSite("lab", "controller-local", model.GatewayModeManaged)
	disabled := false
	state, err := ServiceStateFromModules(site, clientservices.Modules{DNS: &clientservices.DNSConfig{Enabled: &disabled}})
	if err != nil {
		t.Fatal(err)
	}
	if state.DHCP[0].Name != "boetticher_dnsmasq" || state.DHCP[0].Options["disabled"] != "1" || state.DHCP[0].Options["port"] != "0" {
		t.Fatalf("disabled DNS did not disable the native serving instance: %#v", state.DHCP[0])
	}
	if state.Stubby[0].Name != "global" || state.Stubby[0].Options["trigger"] != "boetticher_home" || state.Stubby[0].Lists["dns_transport"][0] != "GETDNS_TRANSPORT_TLS" {
		t.Fatalf("Stubby global section does not use the native contract: %#v", state.Stubby[0])
	}
	if state.System[0].Options["use_dhcp"] != "0" || state.System[0].Options["enabled"] != "1" {
		t.Fatalf("upstream time bootstrap was not retained: %#v", state.System[0])
	}
}

func TestValidateServicePackageRejectsUnownedNativeServiceEntries(t *testing.T) {
	if err := ValidateServicePackage("dhcp", map[string]openwrt.UCISection{
		"factory": {Type: "dnsmasq", Options: map[string]string{}, Lists: map[string][]string{}},
	}, nil); err == nil {
		t.Fatal("unowned dnsmasq instance was accepted")
	}
	if err := ValidateServicePackage("stubby", map[string]openwrt.UCISection{
		"boetticher_resolver_other": {Type: "resolver", Options: map[string]string{}, Lists: map[string][]string{}},
	}, []Section{{Name: "global", Type: "stubby"}}); err == nil {
		t.Fatal("unowned Stubby resolver was accepted")
	}
}

func sectionNames(sections []Section) string {
	names := make([]string, 0, len(sections))
	for _, section := range sections {
		names = append(names, section.Name)
	}
	return strings.Join(names, " ")
}

func boolPtr(value bool) *bool { return &value }
