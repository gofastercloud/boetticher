package dns

import (
	"testing"

	"github.com/dave/labinabox/internal/model"
)

func TestPlanSeparatesStaticAndDynamicZones(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Implementation != "PowerDNS Authoritative" || len(plan.DynamicZones) != 4 || len(plan.ReverseZones) != 4 {
		t.Fatalf("unexpected DNS plan: %#v", plan)
	}
	if plan.DDNS.Source != "OPNsense Kea D2" || len(plan.DDNS.UpdateSources) != 1 || plan.DDNS.UpdateSources[0] != "10.10.99.1" || plan.DDNS.LeaseFailurePolicy != "lease-continues-without-DNS-registration" {
		t.Fatalf("unexpected DDNS boundary: %#v", plan.DDNS)
	}
	if len(plan.AdGuardForwardZones) != 5 {
		t.Fatalf("AdGuard did not receive static and dynamic forwarding zones: %#v", plan.AdGuardForwardZones)
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
