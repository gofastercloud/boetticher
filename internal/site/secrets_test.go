package site

import (
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

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
