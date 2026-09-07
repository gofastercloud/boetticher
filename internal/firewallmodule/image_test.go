package firewallmodule

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureImageReusesPinnedCacheWithoutRunningBuilder(t *testing.T) {
	dir := t.TempDir()
	name := "openwrt-" + OpenWrtVersion + "-" + OpenWrtImageBuilder + "-" + OpenWrtImageContract + "-x86-64.img"
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("qualified image bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	image, err := EnsureImage(context.Background(), ImageSpec{CacheDir: dir, ManagementAddress: "192.168.4.28", ManagementNetmask: "255.255.252.0", ManagementGateway: "192.168.4.1", ControllerAddress: "192.168.4.6", PasswordHash: "hash", BuilderScript: "/does/not/run"})
	if err != nil || image.Name != name || image.SHA256 == "" {
		t.Fatalf("cached image = %#v err=%v", image, err)
	}
}

func TestImageConstantsPinOfficialBuildInputs(t *testing.T) {
	if OpenWrtVersion != "25.12.5" || OpenWrtImageBuilder != "r33051-f5dae5ece4" || !strings.Contains(OpenWrtImageBuilderURL, OpenWrtVersion) || OpenWrtImageProfile != "generic" || OpenWrtImageArchitecture != "x86/64" || OpenWrtImageContract != "v5" || ProviderTLSName != "boetticher-firewall" {
		t.Fatalf("OpenWrt build pins are incomplete")
	}
	if len(OpenWrtPackages) == 0 {
		t.Fatal("OpenWrt package pin is empty")
	}
}

func TestOpenWrtImageACLAllowsOwnedSectionCreation(t *testing.T) {
	builder, err := os.ReadFile(filepath.Join("..", "..", "scripts", "build-openwrt-firewall.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(builder), `"uci": ["set", "add", "delete", "commit", "apply"]`) {
		t.Fatal("OpenWrt rpcd ACL does not allow owned UCI section creation")
	}
}
