package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/site"
	"github.com/gofastercloud/boetticher/internal/usbexport"
)

func TestStaticCredentialReadinessFailsForMissingRequiredProviderCredential(t *testing.T) {
	siteDir := t.TempDir()
	identityPath, recipient := writeTestAgeIdentity(t)
	if err := os.MkdirAll(filepath.Join(siteDir, "secrets"), 0700); err != nil {
		t.Fatal(err)
	}
	s := model.NewDefaultSite("credentials", recipient)
	s.Modules = []model.ResolvedModule{
		{Name: "monitoring", Enabled: true},
		{Name: "litellm", Enabled: true},
		{Name: "aiops", Enabled: true},
	}
	s.ModuleConfig = map[string]model.ModuleConfig{
		"litellm": {Upstreams: []model.LiteLLMUpstreamConfig{{Name: "provider", BaseURL: "https://provider.example/v1", APIKeySecret: "provider_api_key"}}},
	}
	values := map[string]string{"ddns_tsig_secret": "ddns", "pulse_admin_password": "pulse"}
	if err := site.StoreEncryptedDocument(siteDir, recipient, "secrets/boetticher.sops.yaml", values); err != nil {
		t.Fatal(err)
	}
	if err := staticCredentialReadiness(siteDir, s, identityPath); err == nil || !strings.Contains(err.Error(), "provider_api_key") {
		t.Fatalf("missing provider credential was accepted: %v", err)
	}
	values["provider_api_key"] = "provider-secret"
	if err := site.StoreEncryptedDocument(siteDir, recipient, "secrets/boetticher.sops.yaml", values); err != nil {
		t.Fatal(err)
	}
	if err := staticCredentialReadiness(siteDir, s, identityPath); err != nil {
		t.Fatalf("complete static credential set was rejected: %v", err)
	}
}

func TestStaticCredentialReadinessAcceptsRetainedTailnetStateWithoutBootstrapKey(t *testing.T) {
	siteDir := t.TempDir()
	identityPath, recipient := writeTestAgeIdentity(t)
	if err := os.MkdirAll(filepath.Join(siteDir, "secrets"), 0700); err != nil {
		t.Fatal(err)
	}
	s := model.NewDefaultSite("retained-tailnet", recipient)
	s.Modules = []model.ResolvedModule{{Name: "tailnet-router", Enabled: true}}
	s.RetainedModules = []model.RetainedModule{{Module: "tailnet-router", Disposition: "retained"}}
	if err := site.StoreEncryptedDocument(siteDir, recipient, "secrets/boetticher.sops.yaml", map[string]string{"ddns_tsig_secret": "ddns", "pulse_admin_password": "pulse"}); err != nil {
		t.Fatal(err)
	}
	if err := staticCredentialReadiness(siteDir, s, identityPath); err != nil {
		t.Fatalf("valid retained tailnet state was rejected: %v", err)
	}
	s.RetainedModules = nil
	if err := staticCredentialReadiness(siteDir, s, identityPath); err == nil || !strings.Contains(err.Error(), "tailscale_auth_key") {
		t.Fatalf("missing tailnet bootstrap credential was not rejected: %v", err)
	}
}

func TestValidateLiveUSBBindingsRequiresConfiguredIdentityAtConfiguredPort(t *testing.T) {
	manifests := []usbexport.GuestManifest{{Exports: []usbexport.Export{{
		Module: "printer", Requirement: "serial", Port: "1-2.4", VendorID: "1a86", ProductID: "7523", Serial: "printer-01",
	}}}}

	if err := validateLiveUSBBindings(manifests, []configureUSBDevice{{Port: "1-2.4", VendorID: "1a86", ProductID: "7523", Serial: "printer-01"}}); err != nil {
		t.Fatalf("matching live USB identity failed: %v", err)
	}
	for _, test := range []struct {
		name     string
		observed []configureUSBDevice
		want     string
	}{
		{name: "missing", want: "unavailable"},
		{name: "wrong identity", observed: []configureUSBDevice{{Port: "1-2.4", VendorID: "2341", ProductID: "0043", Serial: "printer-01"}}, want: "expected 1a86:7523"},
		{name: "wrong serial", observed: []configureUSBDevice{{Port: "1-2.4", VendorID: "1a86", ProductID: "7523", Serial: "other"}}, want: "different serial"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateLiveUSBBindings(manifests, test.observed)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want substring %q", err, test.want)
			}
		})
	}
}
