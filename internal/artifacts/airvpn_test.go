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
