package firewallmodule

import (
	"context"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/openwrt"
)

func TestDesiredFromReferenceSiteBuildsSixGatewayInterfacesAndPolicy(t *testing.T) {
	state, err := DesiredFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Zones) != 6 || len(state.Network) != 14 {
		t.Fatalf("desired network shape = zones:%d sections:%d", len(state.Zones), len(state.Network))
	}
	for _, section := range state.Network {
		if section.Type == "interface" || section.Type == "device" {
			if section.Options["ipv6"] != "0" {
				t.Fatalf("%s does not disable IPv6: %#v", section.Name, section.Options)
			}
		}
	}
	if len(state.Firewall) < 6*2 {
		t.Fatalf("desired firewall policy is unexpectedly small: %d", len(state.Firewall))
	}
	joined := ""
	for _, section := range state.Firewall {
		joined += section.Name + " " + section.Options["src"] + " " + section.Options["dest"] + "\n"
	}
	for _, want := range []string{"boetticher_home_wan", "boetticher_forward_trusted_servers", "boetticher_forward_trusted_home_wan", "boetticher_forward_sandbox_home_wan", "boetticher_deny_sandbox_home_management", "boetticher_allow_home_api"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("policy is missing %q: %s", want, joined)
		}
	}
	for _, section := range state.Firewall {
		if strings.Contains(section.Name, "_deny_") && strings.HasSuffix(section.Name, "_home_management") && section.Options["dest"] != "home_wan" {
			t.Fatalf("HOME deny %s is not bound to the HOME firewall zone", section.Name)
		}
	}
	for _, forbidden := range []string{"boetticher_forward_sandbox_trusted", "boetticher_forward_servers_trusted", "boetticher_forward_infra_trusted", "boetticher_forward_transit_home_wan"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("policy unexpectedly permits %q: %s", forbidden, joined)
		}
	}
	for _, section := range state.Firewall {
		if section.Name == "boetticher_home_wan" && (section.Options["masq"] != "1" || section.Options["input"] != "DROP") {
			t.Fatalf("HOME/WAN zone does not own NAT and default-deny input: %#v", section)
		}
		if section.Name == "boetticher_allow_home_api" && section.Options["src_ip"] != "192.168.4.6/32" {
			t.Fatalf("Controller API rule is not source-scoped: %#v", section)
		}
		if strings.HasPrefix(section.Name, "boetticher_deny_") && section.Options["dest_ip"] != "192.168.4.0/22" {
			t.Fatalf("LAB-to-HOME deny does not cover the management prefix: %#v", section)
		}
		if strings.HasPrefix(section.Name, "boetticher_zone_") && section.Options["masq"] != "" {
			t.Fatalf("LAB zone owns masquerading: %#v", section)
		}
	}
}

func TestObservabilityFirewallRulesUseExactInternalSourcesAndReservation(t *testing.T) {
	enabled := true
	services := clientservices.Modules{Observability: &clientservices.ObservabilityConfig{Enabled: &enabled}, DHCP: &clientservices.DHCPConfig{Reservations: []clientservices.Reservation{{Name: "lab-companion", Zone: "SERVERS", MAC: "dc:a6:32:e9:dd:82", Address: "10.10.20.10"}}}}
	state, err := DesiredFromSiteWithServices(model.NewSite("installation", "age1example", model.GatewayModeManaged), services)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]Section{}
	for _, section := range state.Firewall {
		seen[section.Name] = section
	}
	for _, test := range []struct {
		name, source, destination, sourceIP, destinationIP, port string
	}{
		{"boetticher_observability_metrics_proxmox", "infra", "mgmt", "10.10.10.20/32", "10.10.99.5/32", "9100"},
		{"boetticher_observability_metrics_controller", "infra", "servers", "10.10.10.20/32", "10.10.20.10/32", "9100"},
		{"boetticher_observability_logs_proxmox", "mgmt", "infra", "10.10.99.5/32", "10.10.10.20/32", "443"},
		{"boetticher_observability_logs_controller", "servers", "infra", "10.10.20.10/32", "10.10.10.20/32", "443"},
	} {
		section, ok := seen[test.name]
		if !ok || section.Options["src"] != test.source || section.Options["dest"] != test.destination || section.Options["src_ip"] != test.sourceIP || section.Options["dest_ip"] != test.destinationIP || section.Options["dest_port"] != test.port {
			t.Fatalf("observability rule %s = %#v", test.name, section)
		}
	}
	services.DHCP.Reservations[0].Address = "10.10.20.11"
	if _, err := DesiredFromSiteWithServices(model.NewSite("installation", "age1example", model.GatewayModeManaged), services); err != nil {
		t.Fatal("reservation address should remain intent-driven: ", err)
	}
}

func TestDesiredFromSiteRejectsNetworkConflicts(t *testing.T) {
	cases := []struct {
		name string
		edit func(*model.Site)
		want string
	}{
		{"duplicate VLAN", func(site *model.Site) { site.Network.Zones[1].VLAN = site.Network.Zones[0].VLAN }, "share VLAN"},
		{"duplicate subnet", func(site *model.Site) {
			site.Network.Zones[1].Network = site.Network.Zones[0].Network
			site.Network.Zones[1].Gateway = "10.10.5.2"
		}, "share subnet"},
		{"gateway outside subnet", func(site *model.Site) { site.Network.Zones[1].Gateway = "10.10.99.1" }, "outside subnet"},
		{"missing required zone", func(site *model.Site) { site.Network.Zones = site.Network.Zones[:5] }, "required network zone"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			site := model.NewSite("installation", "age1example", model.GatewayModeManaged)
			test.edit(&site)
			if _, err := DesiredFromSite(site); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestDiffOwnedPreservesUnrelatedAndUnownedPrefixedSections(t *testing.T) {
	current := map[string]openwrt.UCISection{
		"boetticher_keep":  {Type: "rule", Options: map[string]string{"target": "ACCEPT"}, Lists: map[string][]string{}},
		"boetticher_stale": {Type: "rule", Options: map[string]string{}, Lists: map[string][]string{}},
		"operator_rule":    {Type: "rule", Options: map[string]string{"target": "DROP"}, Lists: map[string][]string{}},
	}
	desired := []Section{{Name: "boetticher_keep", Type: "rule", Options: map[string]string{"target": "ACCEPT"}, Lists: map[string][]string{}}, {Name: "boetticher_new", Type: "rule", Options: map[string]string{"target": "ACCEPT"}, Lists: map[string][]string{}}}
	mutations, err := DiffOwned(current, desired)
	if err != nil {
		t.Fatal(err)
	}
	if len(mutations) != 1 || mutations[0].Kind != MutationCreate {
		t.Fatalf("mutations = %#v", mutations)
	}
}

type fakeWriter struct {
	operations []string
}

func (f *fakeWriter) UCIAddNamed(_ context.Context, _, typ, name string) (string, error) {
	f.operations = append(f.operations, "section:"+typ+":"+name)
	return name, nil
}
func (f *fakeWriter) UCISet(_ context.Context, _, section, option, value string) error {
	f.operations = append(f.operations, "set:"+section+":"+option+":"+value)
	return nil
}
func (f *fakeWriter) UCISetList(_ context.Context, _, section, option string, values []string) error {
	f.operations = append(f.operations, "list:"+section+":"+option+":"+strings.Join(values, ","))
	return nil
}
func (f *fakeWriter) UCIDelete(_ context.Context, _, section, option string) error {
	f.operations = append(f.operations, "delete:"+section+":"+option)
	return nil
}
func (f *fakeWriter) UCIApply(_ context.Context, timeout int) error {
	f.operations = append(f.operations, "apply:"+string(rune(timeout)))
	return nil
}

func TestReconcileOwnedIsNoOpWhenOwnedStateMatches(t *testing.T) {
	section := Section{Name: "boetticher_iface_trusted", Type: "interface", Options: map[string]string{"proto": "static"}, Lists: map[string][]string{}}
	writer := &fakeWriter{}
	changed, err := ReconcileOwned(context.Background(), writer, "network", map[string]openwrt.UCISection{
		section.Name:       {Type: section.Type, Options: map[string]string{"proto": "static"}, Lists: map[string][]string{}},
		"operator_section": {Type: "interface", Options: map[string]string{"proto": "dhcp"}, Lists: map[string][]string{}},
	}, []Section{section})
	if err != nil || changed != 0 || len(writer.operations) != 0 {
		t.Fatalf("no-op reconcile = changed:%d err:%v operations:%v", changed, err, writer.operations)
	}
}

func TestDiffOwnedRemovesManagedStaleReservationButPreservesUnknownPrefix(t *testing.T) {
	current := map[string]openwrt.UCISection{
		"boetticher_host_peer": {Type: "host", Options: map[string]string{"name": "peer", "ip": "10.10.30.225"}, Lists: map[string][]string{}},
		"boetticher_stale":     {Type: "rule", Options: map[string]string{}, Lists: map[string][]string{}},
	}
	mutations, err := DiffOwned(current, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(mutations) != 1 || mutations[0].Kind != MutationDelete || mutations[0].Section.Name != "boetticher_host_peer" {
		t.Fatalf("managed stale mutations = %#v", mutations)
	}
}

func TestReconcileOwnedRefusesConflictingDesiredType(t *testing.T) {
	_, err := ReconcileOwned(context.Background(), &fakeWriter{}, "network", map[string]openwrt.UCISection{
		"boetticher_iface_trusted": {Type: "rule", Options: map[string]string{}, Lists: map[string][]string{}},
	}, []Section{{Name: "boetticher_iface_trusted", Type: "interface", Options: map[string]string{}, Lists: map[string][]string{}}})
	if err == nil || !strings.Contains(err.Error(), "conflicting type") {
		t.Fatalf("type conflict was accepted: %v", err)
	}
}

func TestStageOwnedDoesNotActivate(t *testing.T) {
	writer := &fakeWriter{}
	changed, err := StageOwned(context.Background(), writer, "network", nil, []Section{{Name: "boetticher_stage", Type: "interface", Options: map[string]string{"proto": "static"}, Lists: map[string][]string{}}})
	if err != nil || changed != 1 {
		t.Fatalf("stage = %d, %v", changed, err)
	}
	for _, operation := range writer.operations {
		if strings.HasPrefix(operation, "apply:") {
			t.Fatalf("stage activated UCI: %v", writer.operations)
		}
	}
}
