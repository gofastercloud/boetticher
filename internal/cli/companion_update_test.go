package cli

import (
	"bytes"
	"github.com/gofastercloud/boetticher/internal/model"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdatePulse612PreservesOtherConfiguration(t *testing.T) {
	dir := t.TempDir()
	config := model.ConfigFromSite(model.NewSite("pulse-update", "age1update", model.GatewayModeManaged))
	data, err := model.RenderSiteConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	original := []byte(strings.ReplaceAll(string(data), model.PulseVersion, "6.1.2"))
	path := filepath.Join(dir, "site.yml")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runUpdate([]string{"--site", dir, "--dry-run"}, &output); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, original) {
		t.Fatal("dry-run changed site")
	}
	if err := runUpdate([]string{"--site", dir, "--confirm"}, &output); err != nil {
		t.Fatal(err)
	}
	updated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := model.ParseSiteConfig(updated)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.TestedVersions.Pulse != model.PulseVersion || parsed.Network.Domain != config.Network.Domain {
		t.Fatal("wrong desired-state migration")
	}
	if _, err := os.Stat(filepath.Join(dir, "generated")); !os.IsNotExist(err) {
		t.Fatal("version migration unexpectedly wrote generated state")
	}
}
