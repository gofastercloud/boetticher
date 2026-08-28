package dns

import (
	"net/url"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	"gopkg.in/yaml.v3"
)

func TestPlanSeparatesStaticAndDynamicZones(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Implementation != "PowerDNS Authoritative" || plan.PackageVersion != "4.9.17-1pdns.trixie" || len(plan.DynamicZones) != 3 || len(plan.ReverseZones) != 3 {
		t.Fatalf("unexpected DNS plan: %#v", plan)
	}
	if plan.RecursiveProvider != "blocky" || !plan.AuthoritativeNXDOMAINNoLeak || len(plan.RecursiveUpstreams) < 2 {
		t.Fatalf("default recursive DNS contract is incomplete: %#v", plan)
	}
	if len(plan.AuthoritativeForwardZones) != len(plan.AdGuardForwardZones) || len(plan.AuthoritativeReverseZones) != len(plan.AdGuardReverseZones) {
		t.Fatalf("provider-neutral authoritative zones diverged: %#v", plan)
	}
	if got := plan.AuthoritativeForwardTarget; got != "127.0.0.1:5353" || len(plan.AuthoritativeListenAddresses) != 2 {
		t.Fatalf("incompatible authoritative listener contract: %#v", plan)
	}
	if plan.DDNS.Source != "Kea D2 on lab-fw-01" || len(plan.DDNS.UpdateSources) != 1 || plan.DDNS.UpdateSources[0] != "10.10.99.1" || plan.DDNS.LeaseFailurePolicy != "lease-continues-without-DNS-registration" {
		t.Fatalf("unexpected DDNS boundary: %#v", plan.DDNS)
	}
	if len(plan.AdGuardForwardZones) != 4 || len(plan.AdGuardReverseZones) != 3 {
		t.Fatalf("AdGuard did not receive static and dynamic forwarding zones: %#v", plan.AdGuardForwardZones)
	}
	if !hasRecord(plan.StaticRecords, "proxmox.lab.home.arpa", "10.10.99.5") {
		t.Fatal("Proxmox component URL hostname was not added to the static DNS projection")
	}
	for _, component := range site.PlatformComponents() {
		if component.URL == "" {
			continue
		}
		parsed, err := url.Parse(component.URL)
		if err != nil {
			t.Fatalf("component URL %q is invalid: %v", component.URL, err)
		}
		if !hasRecord(plan.StaticRecords, parsed.Hostname(), component.Address) {
			t.Fatalf("component URL hostname %s has no static DNS record", parsed.Hostname())
		}
	}
	for _, zone := range plan.DDNS.Zones {
		want := TSIGKeyName(zone.SourceZone, model.DefaultDomain)
		if zone.TSIGKeyName != want {
			t.Fatalf("TSIG key for %s = %q, want %q", zone.SourceZone, zone.TSIGKeyName, want)
		}
	}
	name, err := QualifiedName(site, "TRUSTED", "nas01")
	if err != nil || name != "nas01.trusted.lab.home.arpa" {
		t.Fatalf("QualifiedName() = %q, %v", name, err)
	}
	if _, err := QualifiedName(site, "TRUSTED", "monitor"); err == nil {
		t.Fatal("dynamic registration claimed a platform-owned service alias")
	}
	if _, err := QualifiedName(site, "TRUSTED", "lab-dns-01"); err == nil {
		t.Fatal("dynamic registration claimed a platform-owned host label")
	}
	for _, zone := range []string{"TRANSIT", "INFRA", "MGMT"} {
		if _, err := QualifiedName(site, zone, "static-host"); err == nil {
			t.Fatalf("static-only zone %s was accepted for dynamic registration", zone)
		}
	}
	if name, err := QualifiedName(site, "SERVERS", "app-01"); err != nil || name != "app-01.servers.lab.home.arpa" {
		t.Fatalf("SERVERS reservation name = %q, %v", name, err)
	}
}

func TestRecursiveProviderSelectionIsTypedAndProviderNeutral(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	site.ModuleConfig = map[string]model.ModuleConfig{"dns": {Provider: string(model.DNSProviderAdGuard)}}
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	if plan.RecursiveProvider != "adguard" || !plan.AuthoritativeNXDOMAINNoLeak {
		t.Fatalf("explicit provider did not preserve common DNS contract: %#v", plan)
	}
	for _, upstream := range plan.RecursiveUpstreams {
		if strings.Contains(upstream, "lab.home.arpa") {
			t.Fatalf("authoritative namespace leaked into public upstreams: %q", upstream)
		}
	}
}

func TestUserDNSRecordsUseValueAndMayAliasDynamicNames(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	site.DNSRecords = []model.UserDNSRecord{
		{Name: "app.lab.home.arpa", Type: "CNAME", Value: "app-01.servers.lab.home.arpa"},
		{Name: "app-ip.lab.home.arpa", Type: "A", Value: "10.10.20.61"},
	}
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRecordValue(plan.StaticRecords, "app.lab.home.arpa", "CNAME", "app-01.servers.lab.home.arpa", "user") || !hasRecordValue(plan.StaticRecords, "app-ip.lab.home.arpa", "A", "10.10.20.61", "user") {
		t.Fatalf("user DNS records were not projected: %#v", plan.StaticRecords)
	}
	commands := PrimaryCommandPlan(plan)
	foundCNAME := false
	for _, command := range commands {
		if len(command.Args) == 7 && command.Args[1] == "replace-rrset" && command.Args[2] == model.DefaultDomain && command.Args[3] == "app" && command.Args[4] == "CNAME" && command.Args[6] == "app-01.servers.lab.home.arpa" {
			foundCNAME = true
		}
	}
	if !foundCNAME {
		t.Fatalf("CNAME value was not emitted as a PowerDNS target: %#v", commands)
	}
}

func TestUserDNSRecordNamespaceAndPendingDeletionBoundaries(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	site.DNSRecords = []model.UserDNSRecord{{Name: "app.lab.home.arpa", Type: "A", Value: "10.10.20.61"}}
	site.PendingDNSDeletions = []model.DNSDeletion{{Name: "app.lab.home.arpa", Type: "A"}, {Name: "old.lab.home.arpa", Type: "CNAME"}}
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.PendingDeletions) != 1 || plan.PendingDeletions[0].Name != "old.lab.home.arpa" {
		t.Fatalf("present record was not filtered from pending deletion: %#v", plan.PendingDeletions)
	}
	site.PendingDNSDeletions = append(site.PendingDNSDeletions, model.DNSDeletion{Name: "proxmox.lab.home.arpa", Type: "A"})
	plan, err = PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	for _, deletion := range plan.PendingDeletions {
		if deletion.Name == "proxmox.lab.home.arpa" {
			t.Fatal("pending user deletion was allowed to target a current platform RRset")
		}
	}
	commands := PrimaryCommandPlan(plan)
	foundDelete := false
	for _, command := range commands {
		if len(command.Args) == 5 && command.Args[1] == "delete-rrset" && command.Args[3] == "old.lab.home.arpa." && command.Args[4] == "CNAME" {
			foundDelete = true
		}
	}
	if !foundDelete {
		t.Fatalf("pending DNS deletion was not emitted: %#v", commands)
	}
	for _, invalid := range []model.UserDNSRecord{
		{Name: "app.servers.lab.home.arpa", Type: "A", Value: "10.10.20.61"},
		{Name: "proxmox.lab.home.arpa", Type: "A", Value: "10.10.99.5"},
	} {
		candidate := model.NewDefaultSite("installation", "age1example")
		candidate.DNSRecords = []model.UserDNSRecord{invalid}
		if err := candidate.Validate(); err == nil {
			t.Fatalf("invalid user DNS ownership was accepted: %#v", invalid)
		}
	}
}

func TestRenderBlockyConfigPinsAuthoritativeZonesWithoutPublicFallback(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	config, err := RenderBlockyConfig(plan)
	if err != nil {
		t.Fatal(err)
	}
	var decoded BlockyConfig
	if err := yaml.Unmarshal(config, &decoded); err != nil {
		t.Fatalf("Blocky config is not valid YAML: %v", err)
	}
	if len(decoded.Upstreams.Groups["default"]) != 2 || decoded.Upstreams.Groups["default"][0] != "https://cloudflare-dns.com/dns-query" {
		t.Fatalf("unexpected Blocky upstream group: %#v", decoded.Upstreams)
	}
	if strings.Join(decoded.BootstrapDNS, ",") != "1.1.1.1,8.8.8.8" {
		t.Fatalf("unexpected Blocky bootstrap DNS: %#v", decoded.BootstrapDNS)
	}
	if decoded.Conditional.FallbackUpstream {
		t.Fatal("Blocky authoritative mappings allow public fallback")
	}
	if !decoded.DNSSEC.Validate {
		t.Fatal("Blocky DNSSEC validation is not enabled")
	}
	if got := decoded.Blocking.Denylists[FilteringPolicyGroup]; len(got) != 1 || got[0] != FilteringPolicyFile {
		t.Fatalf("unexpected Blocky denylist: %#v", decoded.Blocking.Denylists)
	}
	if got := decoded.Blocking.ClientGroupsBlock["default"]; len(got) != 1 || got[0] != FilteringPolicyGroup {
		t.Fatalf("unexpected Blocky client group: %#v", decoded.Blocking.ClientGroupsBlock)
	}
	for _, zone := range []string{"lab.home.arpa", "servers.lab.home.arpa", "trusted.lab.home.arpa", "sandbox.lab.home.arpa", "20.10.10.in-addr.arpa", "30.10.10.in-addr.arpa", "40.10.10.in-addr.arpa"} {
		if got := decoded.Conditional.Mapping[zone]; got != "127.0.0.1:5353" {
			t.Fatalf("unexpected PowerDNS mapping for %q: %#v", zone, got)
		}
	}
	for _, zone := range []string{"mgmt.lab.home.arpa", "10.10.10.in-addr.arpa"} {
		if _, ok := decoded.Conditional.Mapping[zone]; ok {
			t.Fatalf("static-only zone %q was published as dynamic DNS", zone)
		}
	}
	if decoded.Ports.DNS != 53 || decoded.Caching.MinTime != "5m" {
		t.Fatalf("unexpected Blocky ports/cache config: %#v", decoded)
	}
}

func TestRenderBlockyConfigRejectsOtherProvider(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	plan.RecursiveProvider = string(model.DNSProviderAdGuard)
	if _, err := RenderBlockyConfig(plan); err == nil {
		t.Fatal("Blocky renderer accepted AdGuard provider")
	}
}

func TestExternalPlanPublishesOptionalDDNSContract(t *testing.T) {
	plan, err := PlanFromSite(model.NewSite("installation", "age1example", model.GatewayModeExternal))
	if err != nil {
		t.Fatal(err)
	}
	if plan.DDNS.Enabled || plan.DDNS.Source != "External DHCP/DDNS contract" || len(plan.DDNS.UpdateSources) != 0 || len(plan.DDNS.Zones) != 3 {
		t.Fatalf("external DDNS contract is not optional and complete: %#v", plan.DDNS)
	}
}

func TestExternalPowerDNSPlanDoesNotRequireManagedDDNSSource(t *testing.T) {
	plan, err := PlanFromSite(model.NewSite("installation", "age1example", model.GatewayModeExternal))
	if err != nil {
		t.Fatal(err)
	}
	commands := PrimaryCommandPlan(plan)
	for _, command := range commands {
		if command.SecretStdin || strings.Contains(command.Stdin, DDNSSecretPlaceholder) || strings.Contains(strings.Join(command.Args, " "), "ALLOW-DNSUPDATE") {
			t.Fatalf("external DNS plan unexpectedly includes managed DDNS configuration: %#v", command)
		}
	}
}

func hasRecord(records []StaticRecord, name, address string) bool {
	for _, record := range records {
		if record.Name == name && record.Value == address {
			return true
		}
	}
	return false
}

func hasRecordValue(records []StaticRecord, name, recordType, value, owner string) bool {
	for _, record := range records {
		if record.Name == name && record.Type == recordType && record.Value == value && record.Owner == owner {
			return true
		}
	}
	return false
}

func TestZoneRelativeNameUsesPowerDNSZoneOwners(t *testing.T) {
	for _, test := range []struct {
		name string
		zone string
		want string
	}{
		{name: "portal.lab.home.arpa", zone: "lab.home.arpa", want: "portal"},
		{name: "lab.home.arpa", zone: "lab.home.arpa", want: "@"},
		{name: "portal.lab.home.arpa.", zone: "lab.home.arpa.", want: "portal"},
	} {
		if got := zoneRelativeName(test.name, test.zone); got != test.want {
			t.Fatalf("zoneRelativeName(%q, %q) = %q, want %q", test.name, test.zone, got, test.want)
		}
	}
}

func TestPowerDNSCommandPlanUsesZoneRelativeSyntaxAndNeverEmbedsARealSecret(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	commands := PrimaryCommandPlan(plan)
	if len(commands) == 0 {
		t.Fatal("empty PowerDNS command plan")
	}
	seenTSIG := false
	seenForward := false
	seenReverse := false
	seenZone := false
	seenRecord := false
	seenApex := false
	seenRelativeRecord := false
	for _, command := range commands {
		if command.SecretStdin {
			seenTSIG = true
			if command.Args[0] != "sqlite3" || !strings.Contains(command.Stdin, DDNSSecretPlaceholder) {
				t.Fatalf("TSIG command does not use protected stdin: %#v", command)
			}
			if strings.Contains(strings.Join(command.Args, " "), DDNSSecretPlaceholder) {
				t.Fatal("TSIG placeholder entered the sqlite3 argv")
			}
		}
		if len(command.Args) >= 3 && command.Args[1] == "zone" {
			t.Fatalf("legacy PowerDNS zone command emitted: %#v", command.Args)
		}
		if len(command.Args) >= 3 && command.Args[1] == "create-zone" {
			seenZone = true
		}
		if len(command.Args) >= 5 && command.Args[1] == "set-meta" && command.Args[3] == "ALLOW-DNSUPDATE-FROM" {
			seenForward = true
			seenReverse = seenReverse || strings.Contains(command.Args[2], "in-addr.arpa")
		}
		if len(command.Args) >= 2 && command.Args[1] == "replace-rrset" {
			seenRecord = true
			if command.Args[3] == "@" {
				seenApex = true
			}
			if command.Args[2] == plan.StaticZone && command.Args[3] == "portal" {
				seenRelativeRecord = true
			}
		}
	}
	if !seenTSIG || !seenForward || !seenReverse || !seenZone || !seenRecord || !seenApex || !seenRelativeRecord {
		t.Fatalf("incomplete PowerDNS command plan: %#v", commands)
	}
}

func TestLeaseUpdateAndConflictPolicy(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	update, err := BuildLeaseUpdate(site, "SANDBOX", Lease{LeaseID: "lease-1", Name: "kali", Address: "10.10.40.123", Active: true, State: "active"})
	if err != nil {
		t.Fatal(err)
	}
	if update.ForwardName != "kali.sandbox.lab.home.arpa" || update.ReverseName != "123.40.10.10.in-addr.arpa" || update.Action != "upsert" {
		t.Fatalf("unexpected lease update: %#v", update)
	}
	if _, err := ResolveConflict(Lease{LeaseID: "lease-1", Active: true}, Lease{LeaseID: "lease-2", Active: true}); err == nil {
		t.Fatal("active duplicate name was silently replaced")
	}
	if got, err := ResolveConflict(Lease{LeaseID: "lease-1", Active: true}, Lease{LeaseID: "lease-1", Active: true}); err != nil || got != "update" {
		t.Fatalf("same lease conflict result = %q, %v", got, err)
	}
	updates, err := BuildLeaseReplacement(site, "SANDBOX",
		Lease{LeaseID: "lease-1", Name: "kali", Address: "10.10.40.123", Active: true, State: "active"},
		Lease{LeaseID: "lease-2", Name: "kali", Address: "10.10.40.124", Active: true, State: "active"},
	)
	if err != nil || len(updates) != 2 || updates[0].Action != "delete" || updates[1].Action != "upsert" {
		t.Fatalf("unexpected replacement lifecycle: %#v, %v", updates, err)
	}
}

func TestInvalidHostnameDoesNotCreateRecord(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	if _, err := BuildLeaseUpdate(site, "TRUSTED", Lease{LeaseID: "lease-1", Name: "bad_name", Address: "10.10.30.12", Active: true, State: "active"}); err == nil {
		t.Fatal("unsafe DHCP hostname created a record")
	}
	if _, err := BuildLeaseUpdate(site, "TRUSTED", Lease{LeaseID: "lease-1", Name: "laptop", Address: "10.10.40.12", Active: true, State: "active"}); err == nil {
		t.Fatal("lease outside its zone was accepted")
	}
}
