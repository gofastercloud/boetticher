package site

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/pki"
)

func TestPlatformSecretUpdatePresenceAndRemoval(t *testing.T) {
	siteDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(siteDir, "secrets"), 0700); err != nil {
		t.Fatal(err)
	}
	identityPath, recipient := writeTestAgeIdentity(t)
	if err := StoreEncryptedDocument(siteDir, recipient, "secrets/boetticher.sops.yaml", map[string]string{"openrouter_api_key": "old-value", "unrelated": "keep"}); err != nil {
		t.Fatal(err)
	}
	s := model.Site{SecretMetadata: model.SecretMetadata{AgeRecipient: recipient}}
	if err := UpdatePlatformSecrets(siteDir, s, identityPath, map[string]string{"openrouter_api_key": "new-value"}); err != nil {
		t.Fatal(err)
	}
	presence, err := PlatformSecretPresence(siteDir, s, identityPath, []string{"openrouter_api_key", "missing_key"})
	if err != nil {
		t.Fatal(err)
	}
	if !presence["openrouter_api_key"] || presence["missing_key"] {
		t.Fatalf("unexpected secret presence: %#v", presence)
	}
	changed, err := RemovePlatformSecrets(siteDir, s, identityPath, []string{"openrouter_api_key"})
	if err != nil || !changed {
		t.Fatalf("RemovePlatformSecrets() = %v, %v", changed, err)
	}
	values, err := LoadEncryptedDocument(siteDir, identityPath, "secrets/boetticher.sops.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := values["openrouter_api_key"]; exists || values["unrelated"] != "keep" {
		t.Fatalf("secret removal changed the wrong document content: %#v", values)
	}
}

func TestPlatformSecretCacheReadsOneDocumentAndPreservesMissingKeySemantics(t *testing.T) {
	siteDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(siteDir, "secrets"), 0700); err != nil {
		t.Fatal(err)
	}
	identityPath, recipient := writeTestAgeIdentity(t)
	if err := StoreEncryptedDocument(siteDir, recipient, "secrets/boetticher.sops.yaml", map[string]string{"first": "one", "second": "two"}); err != nil {
		t.Fatal(err)
	}
	s := model.Site{SecretMetadata: model.SecretMetadata{AgeRecipient: recipient}}
	cache, err := LoadPlatformSecretCache(siteDir, s, identityPath)
	if err != nil {
		t.Fatal(err)
	}
	if first, err := cache.Get("first"); err != nil || first != "one" {
		t.Fatalf("cache first value = %q, %v", first, err)
	}
	if second, err := cache.Get("second"); err != nil || second != "two" {
		t.Fatalf("cache second value = %q, %v", second, err)
	}
	if _, err := cache.Get("missing"); !errors.Is(err, ErrPlatformSecretMissing) {
		t.Fatalf("missing cache value error = %v", err)
	}
}

func TestRootKeyIsOutsideRoutinePlatformSecretDocument(t *testing.T) {
	siteDir := t.TempDir()
	identityPath, recipient := writeTestAgeIdentity(t)
	rootIdentityPath, rootRecipient := writeTestAgeIdentity(t)
	s := model.Site{SecretMetadata: model.SecretMetadata{AgeRecipient: recipient, RootAgeRecipient: rootRecipient}}
	authority, err := pki.GenerateAuthority(time.Now().UTC(), "lab.home.arpa")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeEncryptedSecrets(siteDir, s, authority); err != nil {
		t.Fatal(err)
	}
	platform, err := LoadEncryptedDocument(siteDir, identityPath, "secrets/boetticher.sops.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, found := platform["root_key_pem_b64"]; found {
		t.Fatal("routine platform secret document contains the root private key")
	}
	if _, err := LoadEncryptedDocument(siteDir, identityPath, rootAuthoritySecretsPath); err == nil {
		t.Fatal("routine Age identity decrypted the root authority document")
	}
	if _, err := LoadEncryptedDocument(siteDir, rootIdentityPath, "secrets/boetticher.sops.yaml"); err == nil {
		t.Fatal("root Age identity decrypted the routine platform document")
	}
	routine, err := LoadAuthority(siteDir, s, identityPath)
	if err != nil || routine.RootKeyPEM != "" {
		t.Fatalf("routine authority unexpectedly loaded root key: %v", err)
	}
	if _, err := LoadRootCRL(siteDir, routine, time.Now().UTC()); err != nil {
		t.Fatalf("load public root CRL: %v", err)
	}
	if err := atomicWrite(filepath.Join(siteDir, rootCRLPath), []byte("tampered"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRootCRL(siteDir, routine, time.Now().UTC()); err == nil {
		t.Fatal("tampered root CRL was accepted")
	}
	root, err := LoadAuthorityWithRootKey(siteDir, s, identityPath, rootIdentityPath)
	if err != nil || root.RootKeyPEM == "" {
		t.Fatalf("explicit root authority load failed: %v", err)
	}
	wrongRootIdentity, _ := writeTestAgeIdentity(t)
	if _, err := LoadAuthorityWithRootKey(siteDir, s, identityPath, wrongRootIdentity); err == nil {
		t.Fatal("unexpected root identity loaded the root authority")
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

func TestEncryptedDocumentBoundsInputs(t *testing.T) {
	siteDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(siteDir, "secrets"), 0700); err != nil {
		t.Fatal(err)
	}
	identityPath, recipient := writeTestAgeIdentity(t)
	if err := os.WriteFile(filepath.Join(siteDir, "secrets", "document.sops.yaml"), []byte(strings.Repeat("x", MaxEncryptedDocumentBytes+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEncryptedDocument(siteDir, identityPath, "secrets/document.sops.yaml"); err == nil || !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("oversized encrypted input was accepted: %v", err)
	}
	if err := StoreEncryptedDocument(siteDir, recipient, "secrets/document.sops.yaml", map[string]string{"large": strings.Repeat("x", MaxEncryptedDocumentBytes)}); err == nil || !strings.Contains(err.Error(), "input exceeds") {
		t.Fatalf("oversized plaintext input was accepted: %v", err)
	}
}

func TestValidateAgeIdentityRequiresSiteRecipient(t *testing.T) {
	identityPath, recipient := writeTestAgeIdentity(t)
	if err := ValidateAgeIdentity(identityPath, recipient); err != nil {
		t.Fatalf("valid Age identity was rejected: %v", err)
	}

	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAgeIdentity(identityPath, other.Recipient().String()); err == nil || !strings.Contains(err.Error(), "does not match site metadata") {
		t.Fatalf("recipient mismatch was accepted: %v", err)
	}
}

func TestEncryptedSecretRewriteRejectsMutableRecipient(t *testing.T) {
	siteDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(siteDir, "secrets"), 0700); err != nil {
		t.Fatal(err)
	}
	identityPath, recipient := writeTestAgeIdentity(t)
	if err := StoreEncryptedDocument(siteDir, recipient, "secrets/boetticher.sops.yaml", map[string]string{"existing": "value"}); err != nil {
		t.Fatal(err)
	}
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	s := model.Site{SecretMetadata: model.SecretMetadata{AgeRecipient: other.Recipient().String()}}
	if err := UpdatePlatformSecrets(siteDir, s, identityPath, map[string]string{"new": "value"}); err == nil || !strings.Contains(err.Error(), "does not match site metadata") {
		t.Fatalf("mutable recipient was accepted: %v", err)
	}
	values, err := LoadEncryptedDocument(siteDir, identityPath, "secrets/boetticher.sops.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := values["new"]; ok {
		t.Fatal("rejected secret rewrite changed the encrypted document")
	}
}

func TestValidateAgeIdentityRejectsMalformedInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(path, []byte("not-an-age-identity\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateAgeIdentity(path, "age1placeholder"); err == nil {
		t.Fatal("malformed Age identity was accepted")
	}
}

func TestApplyConfigAndPlatformSecretsRollsBackSecretWhenConfigReplacementFails(t *testing.T) {
	siteDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(siteDir, "secrets"), 0700); err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(siteDir, "secrets", "boetticher.sops.yaml")
	identityPath, recipient := writeTestAgeIdentity(t)
	if err := StoreEncryptedDocument(siteDir, recipient, "secrets/boetticher.sops.yaml", map[string]string{"existing": "encrypted"}); err != nil {
		t.Fatal(err)
	}
	originalSecret, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(siteDir, "site.yml"), 0700); err != nil {
		t.Fatal(err)
	}
	s := model.Site{SecretMetadata: model.SecretMetadata{AgeRecipient: "age1test"}}
	config := model.SiteConfig{APIVersion: model.APIVersion}
	s.SecretMetadata.AgeRecipient = recipient
	if err := ApplyConfigAndPlatformSecrets(siteDir, config, s, identityPath, map[string]string{"operator_key": "value"}); err == nil {
		t.Fatal("atomic configure unexpectedly succeeded with an unwritable site.yml target")
	}
	restored, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(originalSecret) {
		t.Fatalf("secret document was not rolled back: %s", restored)
	}
}

func writeTestAgeIdentity(t *testing.T) (string, string) {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(path, []byte(identity.String()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return path, identity.Recipient().String()
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
	declaration := model.ModuleDeclaration{Module: "bifrost", Secrets: []model.SecretDeclaration{{Name: "shared_key"}}}
	s := model.Site{Declarations: []model.ModuleDeclaration{
		declaration,
		{Module: "other", Secrets: []model.SecretDeclaration{{Name: "shared_key"}}},
	}}
	if _, err := moduleSecretOwnership(s, "bifrost", declaration); err == nil {
		t.Fatal("shared module secret was accepted for purge")
	}
}
