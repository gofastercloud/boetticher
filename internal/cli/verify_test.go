package cli

import (
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/portal"
	statusmodel "github.com/gofastercloud/boetticher/internal/status"
)

func TestCheckPlatformOwnershipIncludesComposedLoggingGuest(t *testing.T) {
	managed := model.NewDefaultSite("verify", "age1verify")
	if err := checkPlatformOwnership(managed); err != nil {
		t.Fatalf("managed composed platform was rejected: %v", err)
	}

	external := model.NewSite("verify-external", "age1verify", model.GatewayModeExternal)
	if err := checkPlatformOwnership(external); err != nil {
		t.Fatalf("external composed platform was rejected: %v", err)
	}
}

func TestOfflineVerificationAcceptsAllManagedDynamicDNSZones(t *testing.T) {
	site := model.NewDefaultSite("verify-dns", "age1verify")
	results := offlineVerificationResults(t.TempDir(), site)
	for _, result := range results {
		if result.Name == "DNS/DDNS projection" {
			if result.Status != "STATIC PASS" {
				t.Fatalf("DNS/DDNS projection status = %q, detail = %q", result.Status, result.Detail)
			}
			return
		}
	}
	t.Fatal("DNS/DDNS projection result is missing")
}

func TestVerificationEvidenceUsesExplicitTiers(t *testing.T) {
	results := annotateVerificationEvidence([]portal.CheckResult{
		{Name: "canonical platform model validates", Status: "PASS", Detail: "journey evidence in prose must not change this"},
		{Name: "authenticated SSH journey via Proxmox bastion", Status: "NOT TESTED", Detail: "local wording"},
		{Name: "managed gateway upstream DHCP", Status: "NOT TESTED", Detail: "requires a live query"},
		{Name: "unrecognized check", Status: "NOT TESTED", Detail: "journey evidence"},
	}, "2026-08-29T00:00:00Z")
	want := []statusmodel.EvidenceTier{statusmodel.TierLocal, statusmodel.TierJourney, statusmodel.TierDeployed, statusmodel.TierLocal}
	for index, result := range results {
		if result.Tier != want[index] {
			t.Fatalf("result %q received tier %q, want %q", result.Name, result.Tier, want[index])
		}
		if result.ObservedAt != "2026-08-29T00:00:00Z" {
			t.Fatalf("result %q observed at %q", result.Name, result.ObservedAt)
		}
	}
}
