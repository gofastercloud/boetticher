package firewallmodule

import (
	"context"
	"os"
	"os/exec"
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

func TestOpenWrtVPNHotplugHookScopesAndReappliesIPv6Safety(t *testing.T) {
	builder, err := os.ReadFile(filepath.Join("..", "..", "scripts", "build-openwrt-firewall.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(builder)
	marker := `cat >"$files/etc/hotplug.d/iface/99-boetticher-vpn-safety" <<'EOF'
`
	start := strings.Index(text, marker)
	if start < 0 {
		t.Fatal("VPN hotplug hook heredoc is missing")
	}
	start += len(marker)
	end := strings.Index(text[start:], "\nEOF")
	if end < 0 {
		t.Fatal("VPN hotplug hook heredoc is unterminated")
	}
	hook := text[start : start+end]
	dir := t.TempDir()
	hookPath := filepath.Join(dir, "hook")
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\n"+hook+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "calls")
	sysctl := filepath.Join(dir, "sysctl")
	if err := os.WriteFile(sysctl, []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> "+logPath+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	run := func(action, iface string) error {
		cmd := exec.Command("/bin/sh", hookPath)
		cmd.Env = []string{"ACTION=" + action, "INTERFACE=" + iface, "PATH=" + dir}
		return cmd.Run()
	}
	if err := run("ifup", "wan"); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(logPath); err == nil && len(data) != 0 {
		t.Fatalf("nonmatching hotplug event mutated sysctls: %q", data)
	}
	if err := run("ifup", "airvpn"); err != nil {
		t.Fatal(err)
	}
	if err := run("ifupdate", "airvpn"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(data), "net.ipv6.conf.airvpn.disable_ipv6=1"); got != 2 {
		t.Fatalf("matching hotplug events = %d sysctl applications, want 2: %q", got, data)
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
		`"$ACTION" = ifup`,
		`"$ACTION" = ifupdate`,
		`"$INTERFACE" = airvpn`,
		"/etc/hotplug.d/iface/99-boetticher-vpn-safety",
		`chmod 0755 "$files/etc/hotplug.d/iface/99-boetticher-vpn-safety"`,
		"net.ipv6.conf.airvpn.disable_ipv6=1",
		"net.ipv6.conf.airvpn.autoconf=0",
		"net.ipv6.conf.airvpn.accept_ra=0",
		"net.ipv6.conf.airvpn.forwarding=0",
	} {
		if !strings.Contains(string(builder), required) {
			t.Fatalf("OpenWrt image is missing safety asset contract %q", required)
		}
	}
}
