package site

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestPlatformSecretUpdatePresenceAndRemoval(t *testing.T) {
	siteDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(siteDir, "secrets"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(siteDir, "secrets", "boetticher.sops.yaml"), []byte("openrouter_api_key: old-value\nunrelated: keep\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fakeBin := t.TempDir()
	fakeSOPS := filepath.Join(fakeBin, "sops")
	if err := os.WriteFile(fakeSOPS, []byte("#!/bin/sh\nlast=\"\"\nfor arg do last=\"$arg\"; done\nif [ \"$1\" = \"--decrypt\" ]; then cat \"$last\"; else cat; fi\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	s := model.Site{SecretMetadata: model.SecretMetadata{AgeRecipient: "age1test"}}
	if err := UpdatePlatformSecrets(siteDir, s, "identity", map[string]string{"openrouter_api_key": "new-value"}); err != nil {
		t.Fatal(err)
	}
	presence, err := PlatformSecretPresence(siteDir, s, "identity", []string{"openrouter_api_key", "missing_key"})
	if err != nil {
		t.Fatal(err)
	}
	if !presence["openrouter_api_key"] || presence["missing_key"] {
		t.Fatalf("unexpected secret presence: %#v", presence)
	}
	changed, err := RemovePlatformSecrets(siteDir, s, "identity", []string{"openrouter_api_key"})
	if err != nil || !changed {
		t.Fatalf("RemovePlatformSecrets() = %v, %v", changed, err)
	}
	data, err := os.ReadFile(filepath.Join(siteDir, "secrets", "boetticher.sops.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "openrouter_api_key") || !strings.Contains(string(data), "unrelated") || !strings.Contains(string(data), "keep") {
		t.Fatalf("secret removal changed the wrong document content: %s", data)
	}
}

func TestUpdatePlatformSecretsRejectsUnsafeKeysAndValues(t *testing.T) {
	s := model.Site{SecretMetadata: model.SecretMetadata{AgeRecipient: "age1test"}}
	for key, value := range map[string]string{"../escape": "value", "safe": "", "safe2": "bad\x00value"} {
		if err := UpdatePlatformSecrets(t.TempDir(), s, "identity", map[string]string{key: value}); err == nil {
			t.Fatalf("unsafe platform secret update was accepted for %q", key)
		}
	}
}

func TestPurgeModuleSecretValuesRemovesOnlyDeclaredNames(t *testing.T) {
	values := map[string]any{"tailscale_auth_key": "redacted", "unrelated": "retained"}
	owned := map[string]struct{}{"tailscale_auth_key": {}}
	if !purgeModuleSecretValues(values, owned) {
		t.Fatal("declared module secret purge reported no change")
	}
	if _, exists := values["tailscale_auth_key"]; exists {
		t.Fatal("declared module secret was not removed")
	}
	if values["unrelated"] != "retained" {
		t.Fatal("module secret purge changed unrelated state")
	}
}

func TestPurgeModuleSecretsRefusesSharedDeclaration(t *testing.T) {
	declaration := model.ModuleDeclaration{Module: "litellm", Secrets: []model.SecretDeclaration{{Name: "shared_key"}}}
	s := model.Site{Declarations: []model.ModuleDeclaration{
		declaration,
		{Module: "other", Secrets: []model.SecretDeclaration{{Name: "shared_key"}}},
	}}
	if _, err := moduleSecretOwnership(s, "litellm", declaration); err == nil {
		t.Fatal("shared module secret was accepted for purge")
	}
}
