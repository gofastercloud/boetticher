package cli

import (
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	"github.com/gofastercloud/boetticher/internal/firewalltest"
	"github.com/gofastercloud/boetticher/internal/model"
)

func TestParseClientServiceTestOptionsRejectsContradictoryForms(t *testing.T) {
	for _, args := range [][]string{
		{"--plan", "--yes"},
		{"--plan", "--cleanup-only"},
		{"--cleanup-only"},
	} {
		if _, err := parseClientServiceOptions("module dhcp test", args, true, true, true); err == nil {
			t.Fatalf("options %v were accepted", args)
		}
	}
}

func TestPrepareClientModulesUsesIndependentCopyAndMaterialisesDefaults(t *testing.T) {
	site := model.NewSite("lab", "controller-local", model.GatewayModeManaged)
	enabled := true
	current := clientservices.Modules{DNS: &clientservices.DNSConfig{Enabled: &enabled}}
	proposed, changed, err := prepareClientModules(current, "dns", true, site)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || len(proposed.DNS.Upstreams) != 2 || current.DNS.Upstreams != nil {
		t.Fatalf("prepare did not isolate or materialise intent: current=%#v proposed=%#v", current, proposed)
	}
}

func TestClientServiceTestZonesNeverBorrowsProductionReservation(t *testing.T) {
	site := model.NewSite("lab", "controller-local", model.GatewayModeManaged)
	enabled := true
	modules := clientservices.Modules{DHCP: &clientservices.DHCPConfig{Enabled: &enabled, Scopes: clientservices.DefaultScopes(), Reservations: []clientservices.Reservation{{Name: "operator", Zone: "TRANSIT", MAC: "02:00:00:00:00:01", Address: "10.10.5.61"}}}}
	_, err := clientServiceTestZones(clientServiceContext{Site: site}, modules, "dhcp")
	if err == nil || !strings.Contains(err.Error(), "test-owned") {
		t.Fatalf("production reservation was used for a positive control: %v", err)
	}
}

func TestClientServiceDNSQueriesIncludeExactLocalAAndPTR(t *testing.T) {
	enabled := true
	queries, err := clientServiceDNSQueries(clientservices.Modules{DNS: &clientservices.DNSConfig{Enabled: &enabled, Records: []clientservices.DNSRecord{{Name: "app", Type: "A", Value: "10.10.30.61"}, {Name: "alias", Type: "CNAME", Value: "app"}}}}, model.DefaultDomain)
	if err != nil {
		t.Fatal(err)
	}
	if len(queries) != 5 {
		t.Fatalf("queries=%#v, want public, A, PTR, CNAME, and negative local", queries)
	}
	if queries[1].Expected != "10.10.30.61" || queries[2].Type != "PTR" || queries[2].Expected != "app."+model.DefaultDomain {
		t.Fatalf("local A/PTR query expectations were not exact: %#v", queries)
	}
}

func TestNextTestAddressAndMACSkipOwnedValues(t *testing.T) {
	zone := model.NewSite("lab", "controller-local", model.GatewayModeManaged).Network.Zones[0]
	used := map[string]struct{}{"10.10.5.200": {}, "10.10.5.201": {}}
	address, err := nextTestAddress(zone, used)
	if err != nil || address != "10.10.5.202" {
		t.Fatalf("next test address=%q err=%v", address, err)
	}
	mac := nextTestMAC(0, map[string]struct{}{"02:00:00:4b:4a:00": {}})
	if mac != "02:00:00:4b:4a:01" {
		t.Fatalf("next test MAC=%q", mac)
	}
}

func TestClientServicesRequestRequiresPoolExpectations(t *testing.T) {
	request := firewalltest.Request{Version: firewalltest.ProtocolVersion, Action: "client-services", Service: "dhcp", UseDHCP: true, Domain: model.DefaultDomain, DNSQueries: []firewalltest.DNSQuery{{Name: firewalltest.PublicHost, Type: "A"}}}
	for _, zone := range model.NewSite("lab", "controller-local", model.GatewayModeManaged).Network.Zones {
		request.Zones = append(request.Zones, firewalltest.Zone{Name: zone.Name, Type: string(zone.Type), VLAN: zone.VLAN, Subnet: zone.Network, Gateway: zone.Gateway, DHCPMode: clientservices.ScopePool, PoolStart: "10.10.20.100", PoolEnd: "10.10.20.199"})
	}
	if err := firewalltest.ValidateRequest(request); err == nil {
		t.Fatal("request with wrong-zone pool expectations was accepted")
	}
}

func TestParseNativeDHCPLeaseLinesPreservesRuntimeIdentity(t *testing.T) {
	leases, err := parseNativeDHCPLeaseLines("4102444800 02:00:00:4b:4a:01 10.10.5.240 reserved 010203\n0 02:00:00:4b:4a:02 10.10.20.100 * *\n")
	if err != nil || len(leases) != 2 {
		t.Fatalf("leases=%#v err=%v", leases, err)
	}
	if leases[0].Hostname != "reserved" || leases[0].ClientID != "010203" || leases[1].Hostname != "" || leases[1].Expiry != 0 {
		t.Fatalf("lease identity/expiry was not preserved: %#v", leases)
	}
	if _, err := parseNativeDHCPLeaseLines("not-a-lease"); err == nil {
		t.Fatal("malformed native lease entry was accepted")
	}
}
