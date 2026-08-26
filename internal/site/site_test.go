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
