package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedactHidesSecretShapedFields(t *testing.T) {
	input := map[string]any{"token": "do-not-leak", "nested": map[string]any{"api_key": "also-secret", "label": "visible"}}
	output := redact(input)
	b, err := json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "do-not-leak") || strings.Contains(string(b), "also-secret") {
		t.Fatalf("secret leaked in %s", b)
	}
	if !strings.Contains(string(b), "visible") {
		t.Fatalf("non-secret value was removed: %s", b)
	}
}

func TestSyncHomepageWritesLiveConfigAndArtwork(t *testing.T) {
	root := t.TempDir()
	lab := filepath.Join(root, "lab.yml")
	config := filepath.Join(root, "homepage")
	contents := `api_version: boetticher/v3
network:
  domain: example.test
modules:
  media:
    enabled: true
    application_domain: media.example.test
    aliases:
      jellyfin: jellyfin
control_surfaces:
  - name: Firewall
    description: Appliance admin
    url: https://fw.example.test
    group: Operate
    icon: "⌁"
secret_metadata:
  api_key: should-not-be-written
`
	if err := os.WriteFile(lab, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	if err := syncHomepage(lab, config); err != nil {
		t.Fatal(err)
	}
	services, err := os.ReadFile(filepath.Join(config, "services.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(services), "fw.example.test") || !strings.Contains(string(services), "jellyfin.media.example.test") {
		t.Fatalf("expected published services, got:\n%s", services)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(services)), "-") {
		t.Fatalf("Homepage services must be a list, got:\n%s", services)
	}
	if _, err := os.Stat(filepath.Join(config, "images", "boetticher-cover.jpg")); err != nil {
		t.Fatalf("cover image missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(config, "settings.yaml")); err != nil {
		t.Fatal(err)
	}
}
