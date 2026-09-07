package firewallmodule

import (
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	"github.com/gofastercloud/boetticher/internal/model"
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
	for _, name := range []string{"boetticher_dnsmasq", "boetticher_dhcp_trusted", "boetticher_host_client", "boetticher_record_app"} {
		if !strings.Contains(joined, name) {
			t.Fatalf("shared DHCP/DNS scope omitted %s: %s", name, joined)
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

func sectionNames(sections []Section) string {
	names := make([]string, 0, len(sections))
	for _, section := range sections {
		names = append(names, section.Name)
	}
	return strings.Join(names, " ")
}

func boolPtr(value bool) *bool { return &value }
