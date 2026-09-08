package clientservices

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func testSite() model.Site {
	return model.NewSite("lab", "controller-local", model.GatewayModeManaged)
}

func TestNormalizeMaterializesReferenceDefaultsOnlyInMemory(t *testing.T) {
	modules := Modules{DNS: &DNSConfig{Enabled: boolPtr(true)}, DHCP: &DHCPConfig{Enabled: boolPtr(true)}}
	normalized := modules.Normalize()
	if modules.DNS.Upstreams != nil || modules.DHCP.Scopes != nil || modules.DHCP.LeaseDuration != "" {
		t.Fatal("Normalize mutated caller-owned absent defaults")
	}
	if len(normalized.DNS.Upstreams) != 2 || len(normalized.DHCP.Scopes) != 6 || normalized.DHCP.LeaseDuration != LeaseDuration12Hours {
		t.Fatalf("reference defaults were not materialized: %#v", normalized)
	}
	if err := Validate(normalized, testSite()); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsReservationPoolAndNameConflicts(t *testing.T) {
	modules := Modules{
		DNS:  &DNSConfig{Enabled: boolPtr(true), Records: []DNSRecord{{Name: "app", Type: "A", Value: "10.10.30.61"}}},
		DHCP: &DHCPConfig{Enabled: boolPtr(true), Reservations: []Reservation{{Name: "app", Zone: "TRUSTED", MAC: "02:00:00:00:30:61", Address: "10.10.30.61"}}},
	}
	if err := Validate(modules, testSite()); err == nil || !strings.Contains(err.Error(), "reservation-derived") {
		t.Fatalf("expected reservation/DNS collision, got %v", err)
	}

	modules.DNS.Records = nil
	modules.DHCP.Reservations[0].Address = "10.10.30.100"
	if err := Validate(modules, testSite()); err == nil || !strings.Contains(err.Error(), "dynamic pool") {
		t.Fatalf("expected dynamic-pool collision, got %v", err)
	}
}

func TestValidateRejectsMalformedEncryptedUpstream(t *testing.T) {
	modules := Modules{DNS: &DNSConfig{Enabled: boolPtr(true), Upstreams: []DNSUpstream{{Address: "9.9.9.9", Port: 53, TLSName: "dns.quad9.net"}}}}
	if err := Validate(modules, testSite()); err == nil || !strings.Contains(err.Error(), "TCP 853") {
		t.Fatalf("expected encrypted-upstream validation error, got %v", err)
	}
}

func TestValidateRejectsDHCPWithoutUsableLocalDNS(t *testing.T) {
	if err := Validate(Modules{DHCP: &DHCPConfig{Enabled: boolPtr(true)}}, testSite()); err == nil || !strings.Contains(err.Error(), "enabled local DNS") {
		t.Fatalf("DHCP without DNS was accepted: %v", err)
	}
}

func TestValidateRejectsProbePoolAndRecordTypeCoexistence(t *testing.T) {
	modules := Modules{DNS: &DNSConfig{Enabled: boolPtr(true), Records: []DNSRecord{
		{Name: "alias", Type: "A", Value: "10.10.30.61"},
		{Name: "alias", Type: "CNAME", Value: "target"},
	}}}
	if err := Validate(modules, testSite()); err == nil || !strings.Contains(err.Error(), "both A and CNAME") {
		t.Fatalf("A/CNAME coexistence was accepted: %v", err)
	}

	modules = Modules{DNS: &DNSConfig{Enabled: boolPtr(true)}, DHCP: &DHCPConfig{Enabled: boolPtr(true), Scopes: []DHCPScope{
		{Zone: "TRANSIT", Mode: ScopeReservationsOnly}, {Zone: "INFRA", Mode: ScopeReservationsOnly},
		{Zone: "SERVERS", Mode: ScopePool, PoolStart: "10.10.20.100", PoolEnd: "10.10.20.199"},
		{Zone: "TRUSTED", Mode: ScopePool, PoolStart: "10.10.30.100", PoolEnd: "10.10.30.199"},
		{Zone: "SANDBOX", Mode: ScopePool, PoolStart: "10.10.40.250", PoolEnd: "10.10.40.254"},
		{Zone: "MGMT", Mode: ScopeReservationsOnly},
	}}}
	if err := Validate(modules, testSite()); err == nil || !strings.Contains(err.Error(), "reserved probe") {
		t.Fatalf("probe-address pool was accepted: %v", err)
	}
}

func TestValidateRejectsDanglingAndCyclicAliases(t *testing.T) {
	for _, records := range [][]DNSRecord{
		{{Name: "alias", Type: "CNAME", Value: "missing"}},
		{{Name: "a", Type: "CNAME", Value: "b"}, {Name: "b", Type: "CNAME", Value: "a"}},
	} {
		modules := Modules{DNS: &DNSConfig{Enabled: boolPtr(true), Records: records}}
		if err := Validate(modules, testSite()); err == nil {
			t.Fatalf("invalid alias graph was accepted: %#v", records)
		}
	}
}

func TestVPNRetainedReferencesAndCloneIsolation(t *testing.T) {
	b := true
	m := Modules{DHCP: &DHCPConfig{Reservations: []Reservation{{Name: "peer", Zone: "TRUSTED", MAC: "02:00:00:00:30:61", Address: "10.10.30.225"}}}, VPN: &VPNConfig{Enabled: &b, Location: "europe", Clients: []string{"peer"}, Forwards: []VPNForward{{Name: "web", Reservation: "peer", Protocols: []string{"tcp"}, Port: 443}}}}
	c := m.Clone()
	*c.VPN.Enabled = false
	c.VPN.Clients[0] = "gone"
	if *m.VPN.Enabled == false || m.VPN.Clients[0] != "peer" {
		t.Fatal("clone aliases VPN state")
	}
	c.VPN.Clients[0] = "gone"
	if err := Validate(c, testSite()); err == nil {
		t.Fatal("retained dangling VPN reference accepted")
	}
}

func TestVPNAllowsEnabledLocationWithNoClients(t *testing.T) {
	b := true
	if err := Validate(Modules{VPN: &VPNConfig{Enabled: &b, Location: "europe"}}, testSite()); err != nil {
		t.Fatal(err)
	}
}

func TestVPNClientProtectedRangeBoundaries(t *testing.T) {
	for _, tc := range []struct {
		last     byte
		accepted bool
	}{
		{224, true}, {225, true}, {239, true}, {223, false}, {240, false}, {250, false}, {100, false},
	} {
		b := true
		m := Modules{DHCP: &DHCPConfig{Reservations: []Reservation{{Name: "peer", Zone: "TRUSTED", MAC: "02:00:00:00:30:61", Address: fmt.Sprintf("10.10.30.%d", tc.last)}}}, VPN: &VPNConfig{Enabled: &b, Location: "europe", Clients: []string{"peer"}}}
		if err := Validate(m, testSite()); (err == nil) != tc.accepted {
			t.Errorf("address .%d validation error=%v, want accepted=%v", tc.last, err, tc.accepted)
		}
	}
}

func TestVPNForwardValidationAndRetainedReferences(t *testing.T) {
	b := false
	base := func() Modules {
		return Modules{DHCP: &DHCPConfig{Reservations: []Reservation{{Name: "peer", Zone: "TRUSTED", MAC: "02:00:00:00:30:61", Address: "10.10.30.225"}}}, VPN: &VPNConfig{Enabled: &b, Clients: []string{"peer"}, Forwards: []VPNForward{{Name: "web", Reservation: "peer", Protocols: []string{"tcp", "udp"}, Port: 443}}}}
	}
	if err := Validate(base(), testSite()); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Modules){
		func(m *Modules) { m.DHCP.Reservations = nil },
		func(m *Modules) { m.VPN.Forwards[0].Name = "bad name" },
		func(m *Modules) { m.VPN.Forwards[0].Protocols = []string{"tcp", "tcp"} },
		func(m *Modules) { m.VPN.Forwards[0].Port = 0 },
		func(m *Modules) { m.VPN.Forwards[0].Reservation = "missing" },
	} {
		m := base()
		mutate(&m)
		if err := Validate(m, testSite()); err == nil {
			t.Fatal("invalid retained VPN intent accepted")
		}
	}
}

func TestVPNNormalizeDeepCopiesNestedState(t *testing.T) {
	b := true
	m := Modules{VPN: &VPNConfig{Enabled: &b, Clients: []string{"peer"}, Forwards: []VPNForward{{Protocols: []string{"tcp"}}}}}
	n := m.Normalize()
	*n.VPN.Enabled = false
	n.VPN.Clients[0] = "other"
	n.VPN.Forwards[0].Protocols[0] = "udp"
	if !*m.VPN.Enabled || m.VPN.Clients[0] != "peer" || m.VPN.Forwards[0].Protocols[0] != "tcp" {
		t.Fatal("Normalize aliases VPN state")
	}
}
