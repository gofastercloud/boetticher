package clientservices

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	"gopkg.in/yaml.v3"
)

func testSite() model.Site {
	return model.NewSite("lab", "controller-local", model.GatewayModeManaged)
}

func TestValidateObservabilityContracts(t *testing.T) {
	bad := Modules{Observability: &ObservabilityConfig{Logging: LoggingConfig{RetentionDays: -1}}}
	if err := Validate(bad, testSite()); err == nil || !strings.Contains(err.Error(), "logging.retention_days") {
		t.Fatalf("expected logging retention rejection, got %v", err)
	}
	enabled := true
	bad = Modules{AIOps: &AIOpsConfig{Enabled: &enabled, Holmes: &HolmesConfig{Enabled: &enabled, ModelAlias: "not a label"}}}
	if err := Validate(bad, testSite()); err == nil || !strings.Contains(err.Error(), "holmes.model_alias") {
		t.Fatalf("expected Holmes alias rejection, got %v", err)
	}
	good := Modules{Observability: &ObservabilityConfig{Enabled: &enabled, Logging: LoggingConfig{RetentionDays: 7}, Monitoring: MonitoringConfig{RetentionDays: 30}}}
	if err := Validate(good, testSite()); err != nil {
		t.Fatalf("valid observability intent rejected: %v", err)
	}
	good.Observability.PublicDomain = "davebarton.cc"
	if err := Validate(good, testSite()); err != nil {
		t.Fatalf("valid public observability domain rejected: %v", err)
	}
	good.Observability.PublicDomain = "lab.home.arpa/unsafe"
	if err := Validate(good, testSite()); err == nil || !strings.Contains(err.Error(), "public_domain") {
		t.Fatalf("invalid public observability domain accepted: %v", err)
	}
	good.Observability.PublicDomain = "davebarton.cc"
	good.Observability.Alerts.Pushover = &PushoverConfig{Enabled: &enabled, Title: "Boetticher alerts", Priority: 0}
	if err := Validate(good, testSite()); err != nil {
		t.Fatalf("valid Pushover intent rejected: %v", err)
	}
	for _, priority := range []int{2, 3, -3} {
		good.Observability.Alerts.Pushover.Priority = priority
		if err := Validate(good, testSite()); err == nil || !strings.Contains(err.Error(), "pushover.priority") {
			t.Fatalf("invalid Pushover priority %d accepted: %v", priority, err)
		}
	}
}

func TestPushoverIntentRoundTripsWithoutSecrets(t *testing.T) {
	enabled := true
	modules := Modules{Observability: &ObservabilityConfig{Alerts: AlertsConfig{Pushover: &PushoverConfig{Enabled: &enabled, Title: "Boetticher alerts", Priority: 0}}}}
	data, err := yaml.Marshal(modules)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "token") || strings.Contains(string(data), "user") {
		t.Fatalf("Pushover intent rendered secret fields: %s", data)
	}
	var roundTrip Modules
	if err := yaml.Unmarshal(data, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if roundTrip.Observability == nil || roundTrip.Observability.Alerts.Pushover == nil || roundTrip.Observability.Alerts.Pushover.Title != "Boetticher alerts" {
		t.Fatalf("Pushover intent did not round-trip: %#v", roundTrip)
	}
}

func TestModulesRoundTripPreservesTailnetAndVPNIntent(t *testing.T) {
	enabled := true
	modules := Modules{
		Tailnet: &TailnetConfig{Enabled: true},
		DNS:     &DNSConfig{Enabled: &enabled},
		DHCP:    &DHCPConfig{Enabled: &enabled, Reservations: []Reservation{{Name: "peer", Zone: "TRUSTED", MAC: "02:00:00:00:30:61", Address: "10.10.30.225"}}},
		VPN:     &VPNConfig{Enabled: &enabled, Location: "europe", Clients: []string{"peer"}, Forwards: []VPNForward{{Name: "web", Reservation: "peer", Protocols: []string{"tcp"}, Port: 443}}},
	}
	data, err := yaml.Marshal(modules)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip Modules
	if err := yaml.Unmarshal(data, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if roundTrip.Tailnet == nil || !roundTrip.Tailnet.Enabled || roundTrip.VPN == nil || roundTrip.VPN.Location != "europe" || len(roundTrip.VPN.Forwards) != 1 || roundTrip.VPN.Forwards[0].Reservation != "peer" {
		t.Fatalf("round-trip lost module intent: %#v", roundTrip)
	}
	if err := Validate(roundTrip, testSite()); err != nil {
		t.Fatal(err)
	}
	clone := roundTrip.Clone()
	clone.Tailnet.Enabled = false
	clone.VPN.Clients[0] = "changed"
	clone.VPN.Forwards[0].Protocols[0] = "udp"
	if !roundTrip.Tailnet.Enabled || roundTrip.VPN.Clients[0] != "peer" || roundTrip.VPN.Forwards[0].Protocols[0] != "tcp" {
		t.Fatal("Clone aliases Tailnet or VPN intent")
	}
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

func TestArrstackRequiresProtectedIntentAndAllowsConfiguredPeerPort(t *testing.T) {
	enabled := true
	modules := Modules{
		Media: &MediaConfig{Enabled: true, ApplicationDomain: "media.example.net", Aliases: MediaAliases{Radarr: "radarr", Sonarr: "sonarr", Bazarr: "bazarr", Prowlarr: "prowlarr", Trailarr: "trailarr"}},
		DNS:   &DNSConfig{Enabled: &enabled},
		DHCP:  &DHCPConfig{Enabled: &enabled, Reservations: []Reservation{{Name: "lab-media-01", Zone: "SERVERS", MAC: "02:00:00:00:20:e6", Address: "10.10.20.230"}}},
		VPN:   &VPNConfig{Enabled: &enabled, Location: "europe", Clients: []string{"lab-media-01"}, Forwards: []VPNForward{{Name: "media-qbittorrent", Reservation: "lab-media-01", Protocols: []string{"tcp", "udp"}, Port: 40000}}},
	}
	if err := Validate(modules, testSite()); err != nil {
		t.Fatalf("valid arrstack intent rejected: %v", err)
	}
	stopped := false
	modules.VPN.Enabled = &stopped
	if err := Validate(modules, testSite()); err != nil {
		t.Fatalf("arrstack intent with a retained stopped VPN was rejected: %v", err)
	}
	modules.VPN.Enabled = &enabled
	modules.VPN.Clients = nil
	if err := Validate(modules, testSite()); err == nil {
		t.Fatal("arrstack without VPN client intent accepted")
	}
}

func TestMediaAcceptsGenericDomainAndNamedAliases(t *testing.T) {
	enabled := true
	m := Modules{Media: &MediaConfig{Enabled: true, ApplicationDomain: "media.example.net", Aliases: MediaAliases{Radarr: "movies", Sonarr: "shows", Bazarr: "subs", Prowlarr: "index", Trailarr: "trails"}}, DNS: &DNSConfig{Enabled: &enabled}, DHCP: &DHCPConfig{Enabled: &enabled}, VPN: &VPNConfig{Enabled: &enabled, Location: "europe", Clients: []string{"lab-media-01"}, Forwards: []VPNForward{{Name: "media-qbittorrent", Reservation: "lab-media-01", Protocols: []string{"tcp", "udp"}, Port: 35796}}}}
	m.DHCP.Reservations = []Reservation{{Name: "lab-media-01", Zone: "SERVERS", MAC: "02:00:00:00:20:e6", Address: "10.10.20.230"}}
	if err := Validate(m, testSite()); err != nil {
		t.Fatalf("generic media reference rejected: %v", err)
	}
	m.Media.Aliases.Sonarr = m.Media.Aliases.Radarr
	if err := Validate(m, testSite()); err == nil {
		t.Fatal("duplicate media aliases accepted")
	}
	m.Media.Aliases.Sonarr = "bad alias"
	if err := Validate(m, testSite()); err == nil {
		t.Fatal("malformed media alias accepted")
	}
}

func TestLegacyMediaNormalizeDoesNotInventProductionDomainOrAliases(t *testing.T) {
	normalized := (Modules{Arrstack: &ArrstackConfig{Enabled: true}}).Normalize()
	if normalized.Media == nil || normalized.Media.ApplicationDomain != "" || normalized.Media.Aliases != (MediaAliases{}) {
		t.Fatalf("legacy media normalization invented production values: %#v", normalized.Media)
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
