package site

import (
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
