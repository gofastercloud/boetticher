package artifacts

import (
	"os"
	"strings"
	"testing"
)

func TestAirVPNImageBuildCreatesSystemdRuntimeDirectory(t *testing.T) {
	data, err := os.ReadFile("../../scripts/build-images.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	start := strings.Index(text, "build_airvpn()")
	end := strings.Index(text[start:], "\nbuild_bifrost()")
	if start < 0 || end < 0 || !strings.Contains(text[start:start+end], "install -d -m 0700 \"$rootfs/run/boetticher\"") {
		t.Fatal("AirVPN image build does not pre-create /run/boetticher for systemd namespacing")
	}
}

func TestAirVPNServiceCreatesRuntimeDirectoryBeforeNamespaceSetup(t *testing.T) {
	data, err := os.ReadFile("../../images/airvpn/runtime/boetticher-airvpn.service")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "RuntimeDirectory=boetticher") || !strings.Contains(text, "RuntimeDirectoryMode=0700") {
		t.Fatal("AirVPN service does not ask systemd to create its runtime directory")
	}
}

func TestAirVPNPrepareRemovesOnlyStaleOwnedInterface(t *testing.T) {
	data, err := os.ReadFile("../../images/airvpn/runtime/airvpn-prepare")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, required := range []string{
		"/usr/sbin/ip link show airvpn0",
		"/usr/bin/wg-quick down /run/boetticher/airvpn0.conf",
		"/usr/sbin/ip link delete airvpn0",
		"stale AirVPN interface remains",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("AirVPN prepare helper is missing stale-interface guard %q", required)
		}
	}
}
