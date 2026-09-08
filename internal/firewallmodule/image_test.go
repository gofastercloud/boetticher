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
	if OpenWrtVersion != "25.12.5" || OpenWrtImageBuilder != "r33051-f5dae5ece4" || !strings.Contains(OpenWrtImageBuilderURL, OpenWrtVersion) || OpenWrtImageProfile != "generic" || OpenWrtImageArchitecture != "x86/64" || OpenWrtImageContract != "v8" || ProviderTLSName != "boetticher-firewall" {
		t.Fatalf("OpenWrt build pins are incomplete")
	}
	if len(OpenWrtPackages) == 0 || !containsPackage("wireguard-tools") || !containsPackage("kmod-wireguard") || !containsPackage("ip-full") || !containsPackage("flock") {
		t.Fatal("OpenWrt package pin is empty")
	}
}

func containsPackage(want string) bool {
	for _, packageName := range OpenWrtPackages {
		if packageName == want {
			return true
		}
	}
	return false
}

func TestOpenWrtImageACLAllowsOwnedSectionCreation(t *testing.T) {
	builder, err := os.ReadFile(filepath.Join("..", "..", "scripts", "build-openwrt-firewall.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(builder), `"uci": ["set", "add", "delete", "commit", "apply"]`) || !strings.Contains(string(builder), `"service": ["list"]`) || !strings.Contains(string(builder), `"service": ["event"]`) {
		t.Fatal("OpenWrt rpcd ACL does not allow owned UCI section creation")
	}
	for _, required := range []string{
		"chain-pre/input/10-boetticher-safety.nft",
		"chain-pre/forward/10-boetticher-safety.nft",
		"chain-pre/output/10-boetticher-safety.nft",
		"fw4-stock",
		"flow_offloading_hw='0'",
		"printf '%s\\n' 'v8'",
		"network|zone|device|table|version|help)",
		"flock -n 9",
		"/proc/uptime",
		"HOME inbound protected",
		"removed VPN client",
		"ruleset-pre/10-boetticher-safety-sets.nft",
		"destroy set inet fw4 boetticher_vpn_protected4",
		"exact_sets_json",
		"runtime_safe pre",
		"safety-status",
		"verify_safety_status_sysctls",
		"BOETTICHER_SAFETY_OK",
		"runtime_safe post",
		"partial result, previous runtime permissions may remain",
		"reject_foreign_accepts",
		"reject_foreign_flowtables",
		"nft -j list ruleset",
		"chain_rules()",
		"require_prefix()",
		"lib/preinit/00_boetticher_safety",
		"boot_hook_add preinit_main boetticher_preinit_safety",
		"net.ipv6.conf.all.disable_ipv6=1",
	} {
		if !strings.Contains(string(builder), required) {
			t.Fatalf("OpenWrt image is missing safety asset contract %q", required)
		}
	}
}
