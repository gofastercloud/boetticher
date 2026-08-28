package cli

import (
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
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
