package firewallmodule

import (
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/openwrt"
)

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
