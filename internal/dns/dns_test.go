package dns

import (
	"net/url"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestPlanSeparatesStaticAndDynamicZones(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Implementation != "PowerDNS Authoritative" || plan.PackageVersion != "4.9.17-1pdns.trixie" || len(plan.DynamicZones) != 4 || len(plan.ReverseZones) != 4 {
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
	if len(plan.AdGuardForwardZones) != 5 || len(plan.AdGuardReverseZones) != 4 {
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
	name, err := QualifiedName(site, "SERVERS", "nas01")
	if err != nil || name != "nas01.servers.lab.home.arpa" {
		t.Fatalf("QualifiedName() = %q, %v", name, err)
	}
	if _, err := QualifiedName(site, "SERVERS", "monitor"); err == nil {
		t.Fatal("dynamic registration claimed a platform-owned service alias")
	}
	if _, err := QualifiedName(site, "SERVERS", "lab-dns-01"); err == nil {
		t.Fatal("dynamic registration claimed a platform-owned host label")
	}
}

func TestRecursiveProviderSelectionIsTypedAndProviderNeutral(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	site.ModuleConfig = map[string]model.ModuleConfig{}
	site.ModuleConfig["dns"] = model.ModuleConfig{Provider: string(model.DNSProviderAdGuard)}
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

func TestExternalPlanPublishesOptionalDDNSContract(t *testing.T) {
	plan, err := PlanFromSite(model.NewSite("installation", "age1example", model.GatewayModeExternal))
	if err != nil {
		t.Fatal(err)
	}
	if plan.DDNS.Enabled || plan.DDNS.Source != "External DHCP/DDNS contract" || len(plan.DDNS.UpdateSources) != 0 || len(plan.DDNS.Zones) != 4 {
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
		if record.Name == name && record.Address == address {
			return true
		}
	}
	return false
}

func TestPowerDNSCommandPlanUsesQualifiedSyntaxAndNeverEmbedsARealSecret(t *testing.T) {
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
		if len(command.Args) >= 3 && command.Args[1] == "create-zone" {
			t.Fatalf("legacy PowerDNS zone command emitted: %#v", command.Args)
		}
		if len(command.Args) >= 5 && command.Args[1] == "metadata" && command.Args[4] == "ALLOW-DNSUPDATE-FROM" {
			seenForward = true
			seenReverse = seenReverse || command.Args[3] == "10.10.10.in-addr.arpa"
		}
	}
	if !seenTSIG || !seenForward || !seenReverse {
		t.Fatalf("incomplete PowerDNS command plan: %#v", commands)
	}
}

func TestLeaseUpdateAndConflictPolicy(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	update, err := BuildLeaseUpdate(site, "SANDBOX", Lease{LeaseID: "lease-1", Name: "kali", Address: "10.10.50.123", Active: true, State: "active"})
	if err != nil {
		t.Fatal(err)
	}
	if update.ForwardName != "kali.sandbox.lab.home.arpa" || update.ReverseName != "123.50.10.10.in-addr.arpa" || update.Action != "upsert" {
		t.Fatalf("unexpected lease update: %#v", update)
	}
	if _, err := ResolveConflict(Lease{LeaseID: "lease-1", Active: true}, Lease{LeaseID: "lease-2", Active: true}); err == nil {
		t.Fatal("active duplicate name was silently replaced")
	}
	if got, err := ResolveConflict(Lease{LeaseID: "lease-1", Active: true}, Lease{LeaseID: "lease-1", Active: true}); err != nil || got != "update" {
		t.Fatalf("same lease conflict result = %q, %v", got, err)
	}
	updates, err := BuildLeaseReplacement(site, "SANDBOX",
		Lease{LeaseID: "lease-1", Name: "kali", Address: "10.10.50.123", Active: true, State: "active"},
		Lease{LeaseID: "lease-2", Name: "kali", Address: "10.10.50.124", Active: true, State: "active"},
	)
	if err != nil || len(updates) != 2 || updates[0].Action != "delete" || updates[1].Action != "upsert" {
		t.Fatalf("unexpected replacement lifecycle: %#v, %v", updates, err)
	}
}

func TestInvalidHostnameDoesNotCreateRecord(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	if _, err := BuildLeaseUpdate(site, "TRUSTED", Lease{LeaseID: "lease-1", Name: "bad_name", Address: "10.10.10.12", Active: true, State: "active"}); err == nil {
		t.Fatal("unsafe DHCP hostname created a record")
	}
	if _, err := BuildLeaseUpdate(site, "TRUSTED", Lease{LeaseID: "lease-1", Name: "laptop", Address: "10.10.50.12", Active: true, State: "active"}); err == nil {
		t.Fatal("lease outside its zone was accepted")
	}
}
