package cli

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
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

func TestOfflineVerificationUsesSuppliedEndpointResolver(t *testing.T) {
	config := model.ConfigFromSite(model.NewDefaultSite("verify-endpoint", "age1verifyendpoint"))
	enabled := true
	config.Modules.TailnetRouter = &model.ToggleModuleConfig{Enabled: &enabled}
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	results := offlineVerificationResultsWithResolver(t.TempDir(), site, func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("198.51.100.30")}, nil
	})
	for _, result := range results {
		if result.Name == "firewall policy projection" {
			if result.Status != "STATIC PASS" {
				t.Fatalf("firewall policy projection status = %q, detail = %q", result.Status, result.Detail)
			}
			return
		}
	}
	t.Fatal("firewall policy projection result is missing")
}

func TestOfflineVerificationPreservesEndpointResolutionHold(t *testing.T) {
	config := model.ConfigFromSite(model.NewDefaultSite("verify-endpoint-hold", "age1verifyendpointhold"))
	enabled := true
	config.Modules.TailnetRouter = &model.ToggleModuleConfig{Enabled: &enabled}
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	results := offlineVerificationResultsWithResolver(t.TempDir(), site, func(host string) ([]net.IP, error) {
		return nil, fmt.Errorf("resolver unavailable for %s", host)
	})
	for _, result := range results {
		if result.Name == "firewall policy projection" {
			if result.Status != "FAIL" || !strings.Contains(result.Detail, "HOLD: resolve endpoint") {
				t.Fatalf("endpoint resolution failure was not preserved: %#v", result)
			}
			return
		}
	}
	t.Fatal("firewall policy projection result is missing")
}

func TestVerificationEvidenceUsesExplicitTiers(t *testing.T) {
	results, err := annotateVerificationEvidence([]portal.CheckResult{
		{Name: "canonical platform model validates", Status: "PASS", Detail: "journey evidence in prose must not change this"},
		{Name: "authenticated SSH journey via Proxmox bastion", Status: "NOT TESTED", Detail: "local wording"},
		{Name: "managed gateway upstream DHCP", Status: "NOT TESTED", Detail: "requires a live query"},
	}, "2026-08-29T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	want := []statusmodel.EvidenceTier{statusmodel.TierLocal, statusmodel.TierJourney, statusmodel.TierDeployed}
	for index, result := range results {
		if result.Tier != want[index] {
			t.Fatalf("result %q received tier %q, want %q", result.Name, result.Tier, want[index])
		}
		if result.ObservedAt != "2026-08-29T00:00:00Z" {
			t.Fatalf("result %q observed at %q", result.Name, result.ObservedAt)
		}
	}
}

func TestVerificationEvidenceRejectsUnknownChecks(t *testing.T) {
	if _, err := annotateVerificationEvidence([]portal.CheckResult{{Name: "unrecognized check", Status: "PASS"}}, "2026-08-29T00:00:00Z"); err == nil || !strings.Contains(err.Error(), "not in the evidence contract") {
		t.Fatalf("unknown verification check was accepted: %v", err)
	}
}

func TestHealthResultsOmitQualificationOnlyChecks(t *testing.T) {
	site := model.NewDefaultSite("health-results", "age1healthresults")
	results, _, err := collectHealthResults(healthOptions{siteDir: t.TempDir(), sshPath: t.TempDir() + "/missing"}, site)
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range results {
		if result.Status == "NOT TESTED" {
			t.Fatalf("health result was left unknowable: %#v", result)
		}
		switch result.Name {
		case "DNS01/DNS02 reachable", "NTP01/NTP02 synchronized", "Proxmox API least privilege", "portal requires client certificate", "Pulse requires client certificate", "latest VM/LXC backup", "Age recovery fixture", "SANDBOX cannot access TRUSTED", "SANDBOX cannot access SERVERS", "SANDBOX cannot access MGMT", "TRANSIT/INFRA/MGMT are static-only; SERVERS is reservation-only":
			t.Fatalf("qualification-only check was included: %#v", result)
		}
	}
}

func TestCheckRevisionFileRequiresTheAuthoritativeRevisionField(t *testing.T) {
	dir := t.TempDir()
	revision := "sha256:expected"
	cases := []struct {
		name    string
		ext     string
		content string
		wantErr bool
	}{
		{name: "json exact", ext: ".json", content: `{"model_revision":"sha256:expected","detail":"sha256:other"}`},
		{name: "json unrelated occurrence", ext: ".json", content: `{"model_revision":"sha256:wrong","detail":"sha256:expected"}`, wantErr: true},
		{name: "inventory exact", ext: ".ini", content: "# Generated by boetticher.\n# Model revision: sha256:expected\n"},
		{name: "inventory prefix mismatch", ext: ".ini", content: "# Model revision: sha256:expected-old\n", wantErr: true},
		{name: "ssh exact", ext: ".conf", content: "# boetticher-model-revision: sha256:expected\n"},
		{name: "ssh prefix mismatch", ext: ".conf", content: "# boetticher-model-revision: sha256:expected-old\n", wantErr: true},
		{name: "portal exact", ext: ".html", content: "<p>Lab revision: <code>sha256:expected</code></p>"},
		{name: "portal unrelated occurrence", ext: ".html", content: "<p>sha256:expected</p>", wantErr: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(dir, test.name+test.ext)
			if err := os.WriteFile(path, []byte(test.content), 0600); err != nil {
				t.Fatal(err)
			}
			err := checkRevisionFile(path, revision)
			if test.wantErr && err == nil {
				t.Fatal("stale or unrelated revision was accepted")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("current revision was rejected: %v", err)
			}
		})
	}
}
