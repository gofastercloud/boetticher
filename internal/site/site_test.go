package site

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSafeSitePathRejectsEscapes(t *testing.T) {
	for _, relative := range []string{"../secrets", "/tmp/secrets", "../../outside"} {
		if _, err := safeSitePath(t.TempDir(), relative); err == nil {
			t.Errorf("safeSitePath accepted %q", relative)
		}
	}
	path, err := safeSitePath(t.TempDir(), filepath.Join("secrets", "one.sops.yaml"))
	if err != nil || !strings.HasSuffix(path, filepath.Join("secrets", "one.sops.yaml")) {
		t.Fatalf("safeSitePath valid path = %q, %v", path, err)
	}
}

func TestInitialSiteGitignoreExcludesArtifactRuntime(t *testing.T) {
	for _, entry := range []string{"generated/artifacts/", "generated/runtime/", "*.tar.zst", "*.qcow2", ".trivy/"} {
		if !strings.Contains(initialSiteGitignore, entry) {
			t.Fatalf("initial site gitignore does not exclude %s", entry)
		}
	}
}

func TestCreateAgeIdentityReusesExistingIdentity(t *testing.T) {
	toolDir := t.TempDir()
	toolPath := filepath.Join(toolDir, "age-keygen")
	tool := "#!/bin/sh\n[ \"$1\" = \"-y\" ] || exit 1\nprintf '%s\\n' age1existingrecipient\n"
	if err := os.WriteFile(toolPath, []byte(tool), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", toolDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	identityPath := filepath.Join(t.TempDir(), "identity.txt")
	original := []byte("existing identity")
	if err := os.WriteFile(identityPath, original, 0o600); err != nil {
		t.Fatal(err)
	}

	recipient, err := createAgeIdentity(identityPath)
	if err != nil {
		t.Fatalf("reuse existing Age identity: %v", err)
	}
	if recipient != "age1existingrecipient" {
		t.Fatalf("recipient = %q, want existing identity recipient", recipient)
	}
	got, err := os.ReadFile(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("existing Age identity was changed: %q", got)
	}
}
