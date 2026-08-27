package model

import (
	"strings"
	"testing"
)

func TestRevisionIsIndependentOfComponentOrder(t *testing.T) {
	first := NewDefaultSite("installation", "age1example")
	first.TestedVersions.Gateway = QualifiedGatewayImage
	second := first
	second.Components = append([]Component(nil), first.Components...)
	for i, j := 0, len(second.Components)-1; i < j; i, j = i+1, j-1 {
		second.Components[i], second.Components[j] = second.Components[j], second.Components[i]
	}
	a, err := first.Revision()
	if err != nil {
		t.Fatal(err)
	}
	b, err := second.Revision()
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("revisions differ for equivalent component sets: %s != %s", a, b)
	}
}

func TestOfficialModuleDeclarationsDoNotBecomePlatformComponents(t *testing.T) {
	without := NewDefaultSite("installation", "age1example")
	with := without
	with.Modules = []ResolvedModule{{Name: "future-remote-access", Enabled: true}}

	withoutRevision, err := without.Revision()
	if err != nil {
		t.Fatal(err)
	}
	withRevision, err := with.Revision()
	if err != nil {
		t.Fatal(err)
	}
	if withoutRevision == withRevision {
		t.Fatal("module declaration was omitted from the canonical model revision")
	}
	if len(with.PlatformComponents()) != len(without.PlatformComponents()) {
		t.Fatal("official module declaration changed the core component projection")
	}
}

func TestRevisionIsIndependentOfOfficialModuleOrder(t *testing.T) {
	first := NewDefaultSite("installation", "age1example")
	first.Modules = []ResolvedModule{{Name: "z-module", Enabled: true}, {Name: "a-module", Enabled: false}}
	second := first
	second.Modules = []ResolvedModule{{Name: "a-module", Enabled: false}, {Name: "z-module", Enabled: true}}
	a, err := first.Revision()
	if err != nil {
		t.Fatal(err)
	}
	b, err := second.Revision()
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("revisions differ for equivalent module sets: %s != %s", a, b)
	}
}

func TestRevisionIgnoresOperatorLocalSSHPath(t *testing.T) {
	first := NewDefaultSite("installation", "age1example")
	second := first
	first.TestedVersions.Gateway = QualifiedGatewayImage
	second.TestedVersions.Gateway = QualifiedGatewayImage
	second.SSHIdentityFile = "/different/operator/key"
	a, err := first.Revision()
	if err != nil {
		t.Fatal(err)
	}
	b, err := second.Revision()
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("operator-local SSH path changed platform revision: %s != %s", a, b)
	}
}

func TestRevisionIgnoresPendingDNSDeletionRuntimeState(t *testing.T) {
	first := NewDefaultSite("installation", "age1example")
	second := first
	second.PendingDNSDeletions = []DNSDeletion{{Name: "old.lab.home.arpa", Type: "A"}}
	firstRevision, err := first.Revision()
	if err != nil {
		t.Fatal(err)
	}
	secondRevision, err := second.Revision()
	if err != nil {
		t.Fatal(err)
	}
	if firstRevision != secondRevision {
		t.Fatalf("runtime DNS deletion state changed canonical revision: %s != %s", firstRevision, secondRevision)
	}
}

func TestUnqualifiedGatewayImageIsRejected(t *testing.T) {
	site := NewDefaultSite("installation", "age1example")
	site.TestedVersions.Gateway = "debian-13-genericcloud-amd64-old"
	if err := site.Validate(); err == nil {
		t.Fatal("unqualified gateway image was accepted")
	}
}

func TestExternalGatewayOmitsManagedFirewall(t *testing.T) {
	site := NewSite("installation", "age1example", GatewayModeExternal)
	if err := site.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, component := range site.Components {
		if component.Name == "lab-fw-01" {
			t.Fatal("external gateway site retained managed firewall component")
		}
	}
}

func TestTransitIsFixedCoreNetworkAndSemanticPlacement(t *testing.T) {
	site := NewSite("installation", "age1example", GatewayModeManaged)
	transit, err := site.ZoneForType(ZoneTypeTransit)
	if err != nil {
		t.Fatal(err)
	}
	if transit.Name != "TRANSIT" || transit.Type != ZoneTypeTransit || transit.VLAN != TransitVLAN || transit.Network != TransitNetwork || transit.Gateway != TransitGateway {
		t.Fatalf("unexpected TRANSIT contract: %#v", transit)
	}
	if err := site.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := site.ZoneForType(ZoneType("unknown")); err == nil {
		t.Fatal("unknown semantic zone type was accepted")
	}
}

func TestCoreZonesUseCanonicalNetworkContract(t *testing.T) {
	site := NewSite("installation", "age1example", GatewayModeManaged)
	want := map[string]Zone{
		"TRANSIT": {Name: "TRANSIT", Type: ZoneTypeTransit, VLAN: 5, Network: "10.10.5.0/24", Gateway: "10.10.5.1", AddressMode: "none"},
		"INFRA":   {Name: "INFRA", Type: ZoneTypeInfrastructure, VLAN: 10, Network: "10.10.10.0/24", Gateway: "10.10.10.1", AddressMode: "static"},
		"SERVERS": {Name: "SERVERS", Type: ZoneTypeServers, VLAN: 20, Network: "10.10.20.0/24", Gateway: "10.10.20.1", AddressMode: "reservations-only"},
		"TRUSTED": {Name: "TRUSTED", Type: ZoneTypeTrusted, VLAN: 30, Network: "10.10.30.0/24", Gateway: "10.10.30.1", AddressMode: "dynamic-reservations"},
		"SANDBOX": {Name: "SANDBOX", Type: ZoneTypeSandbox, VLAN: 40, Network: "10.10.40.0/24", Gateway: "10.10.40.1", AddressMode: "dynamic"},
		"MGMT":    {Name: "MGMT", Type: ZoneTypeManagement, VLAN: 99, Network: "10.10.99.0/24", Gateway: "10.10.99.1", AddressMode: "static"},
	}
	if len(site.Network.Zones) != len(want) {
		t.Fatalf("got %d zones, want %d", len(site.Network.Zones), len(want))
	}
	for _, zone := range site.Network.Zones {
		expected, ok := want[zone.Name]
		if !ok || zone.Name != expected.Name || zone.Type != expected.Type || zone.VLAN != expected.VLAN || zone.Network != expected.Network || zone.Gateway != expected.Gateway || zone.AddressMode != expected.AddressMode {
			t.Errorf("unexpected zone: %#v", zone)
		}
	}
	if got := site.Components[0].Address; got != ProxmoxManagementAddress {
		t.Fatalf("Proxmox management address = %s, want %s", got, ProxmoxManagementAddress)
	}
	if err := site.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestCoreInfrastructureUsesInfraAddresses(t *testing.T) {
	site := NewDefaultSite("installation", "age1example")
	want := map[string]string{
		"lab-dns-01":     "10.10.10.10",
		"lab-dns-02":     "10.10.10.11",
		"lab-monitor-01": "10.10.10.20",
		"lab-log-01":     "10.10.10.40",
		"lab-portal-01":  "10.10.10.30",
	}
	found := make(map[string]bool, len(want))
	for _, component := range site.Components {
		address, ok := want[component.Name]
		if !ok {
			continue
		}
		if component.Zone != "INFRA" || component.Address != address {
			t.Errorf("%s projection = zone %s, address %s; want INFRA, %s", component.Name, component.Zone, component.Address, address)
		}
		found[component.Name] = true
	}
	for name := range want {
		if !found[name] {
			t.Errorf("default site is missing Core infrastructure component %s", name)
		}
	}
}

func TestUserNetworkIntentValidatesReservationsAndDNSOwnership(t *testing.T) {
	site := NewDefaultSite("installation", "age1example")
	site.DHCPReservations = []DHCPReservation{{Zone: "SERVERS", Hostname: "app-01", Address: "10.10.20.61", MAC: "02:00:00:00:02:61", VMID: 550}}
	site.DNSRecords = []UserDNSRecord{
		{Name: "app.lab.home.arpa", Type: "CNAME", Value: "app-01.servers.lab.home.arpa"},
		{Name: "app-ip.lab.home.arpa", Type: "A", Value: "10.10.20.61"},
	}
	if err := site.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []Site{
		func() Site {
			value := site
			value.DHCPReservations = []DHCPReservation{{Zone: "TRUSTED", Hostname: "app-01", Address: "10.10.20.61", MAC: "02:00:00:00:02:61"}}
			return value
		}(),
		func() Site {
			value := site
			value.DNSRecords = []UserDNSRecord{{Name: "app-01.servers.lab.home.arpa", Type: "A", Value: "10.10.20.61"}}
			return value
		}(),
		func() Site {
			value := site
			value.DNSRecords = []UserDNSRecord{{Name: "app.lab.home.arpa", Type: "TXT", Value: "bad"}}
			return value
		}(),
	} {
		if err := invalid.Validate(); err == nil {
			t.Fatal("invalid user network intent was accepted")
		}
	}
}

func TestUserCNAMECyclesAreRejected(t *testing.T) {
	site := NewDefaultSite("installation", "age1example")
	site.DNSRecords = []UserDNSRecord{
		{Name: "one.lab.home.arpa", Type: "CNAME", Value: "two.lab.home.arpa"},
		{Name: "two.lab.home.arpa", Type: "CNAME", Value: "one.lab.home.arpa"},
	}
	if err := site.Validate(); err == nil {
		t.Fatal("CNAME cycle was accepted")
	}
}

func TestUnknownZoneSemanticTypeIsRejected(t *testing.T) {
	site := NewSite("installation", "age1example", GatewayModeManaged)
	for index := range site.Network.Zones {
		if site.Network.Zones[index].Name == "TRANSIT" {
			site.Network.Zones[index].Type = ZoneType("edge")
		}
	}
	if err := site.Validate(); err == nil || !strings.Contains(err.Error(), "unknown semantic type") {
		t.Fatalf("unknown zone semantic type was accepted: %v", err)
	}
}

func TestNetworkIntentCannotCarryRawFirewallCommand(t *testing.T) {
	site := NewDefaultSite("installation", "age1example")
	site.Declarations = []ModuleDeclaration{{
		Module:         "example",
		Artifact:       Artifact{DefinitionSHA256: strings.Repeat("a", 64)},
		NetworkIntents: []NetworkIntent{{Source: "nft add rule", Destination: "SERVERS", Protocol: "tcp", Ports: []string{"443"}, Direction: "egress", Purpose: "unsafe"}},
	}}
	if err := site.Validate(); err == nil || !strings.Contains(err.Error(), "safe references") {
		t.Fatalf("raw firewall command was accepted as a network intent: %v", err)
	}
}

func TestOldSiteSchemaRequiresFreshV03Initialization(t *testing.T) {
	site := NewDefaultSite("installation", "age1example")
	site.APIVersion = "boetticher/v1"
	site.SchemaVersion = 1
	err := site.Validate()
	if err == nil || !strings.Contains(err.Error(), "recreate the site with boetticher init") {
		t.Fatalf("old schema did not produce the recreation guidance: %v", err)
	}
}

func TestUserManagedVMIDMustUseReservedRange(t *testing.T) {
	site := NewDefaultSite("installation", "age1example")
	site.Components = append(site.Components, Component{Name: "user-vm", VMID: 450, Hostname: "user-vm", Zone: "SANDBOX", Address: "10.10.40.50", Role: "user workload"})
	if err := site.Validate(); err == nil || !strings.Contains(err.Error(), "reserved user-workload range") {
		t.Fatalf("invalid user VMID was accepted: %v", err)
	}
}

func TestPlatformGuestsCarryCanonicalTags(t *testing.T) {
	site := NewDefaultSite("installation", "age1example")
	for _, component := range site.PlatformComponents() {
		if !component.ProductOwned {
			continue
		}
		for _, required := range []string{TagBoetticher, TagManaged} {
			if !containsString(component.Tags, required) {
				t.Fatalf("platform component %s is missing %q: %#v", component.Name, required, component.Tags)
			}
		}
		if component.VMID != 0 && component.Backup && !containsString(component.Tags, TagBackup) {
			t.Fatalf("backed-up platform guest %s is missing %q: %#v", component.Name, TagBackup, component.Tags)
		}
	}
}

func TestModuleOwnershipTagIsCanonicalAndFailClosed(t *testing.T) {
	if got := ModuleOwnershipTag("dns"); got != "boetticher-module-dns" {
		t.Fatalf("module ownership tag = %q, want canonical tag", got)
	}
	for _, invalid := range []string{"", "dns/other", "dns other", "dns\nother"} {
		if got := ModuleOwnershipTag(invalid); got != "" {
			t.Fatalf("invalid module name %q produced ownership tag %q", invalid, got)
		}
	}
}

func TestBackedUpPlatformGuestRequiresBackupTag(t *testing.T) {
	site := NewDefaultSite("installation", "age1example")
	for i := range site.Components {
		if site.Components[i].Name == "lab-dns-01" {
			tags := []string{}
			for _, tag := range site.Components[i].Tags {
				if tag != TagBackup {
					tags = append(tags, tag)
				}
			}
			site.Components[i].Tags = tags
		}
	}
	if err := site.Validate(); err == nil || !strings.Contains(err.Error(), "missing required tag \"backup\"") {
		t.Fatalf("missing backup tag was accepted: %v", err)
	}
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
