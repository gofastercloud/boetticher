package arrstack

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGuestPolicyAllowsOnlyRequiredArrstackJourneys(t *testing.T) {
	policy, err := GuestPolicyScript(QBitTorrentPort)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"bridge=btcr-arrstack0", "subnet=172.30.20.0/24", "gateway=10.10.20.1", "guest_mac=02:00:00:00:20:e6",
		"ip daddr \"$gateway\" tcp dport 53 accept", "udp dport { 53, 123 } accept",
		"ip saddr { 10.10.30.0/24, 10.10.5.10 } tcp dport 443 accept",
		"tcp dport 35796 accept", "udp dport 35796 accept", "snat to 10.10.20.230", "priority srcnat - 1",
	} {
		if !strings.Contains(policy, want) {
			t.Fatalf("required positive path missing: %q", want)
		}
	}
	for _, want := range []string{
		"meta nfproto ipv6 drop", "100.64.0.0/10", "172.16.0.0/12", "224.0.0.0/4",
		"ip saddr $private4 drop", "ip daddr $private4 drop", "ip saddr != 10.10.20.230 drop", "-A DOCKER-USER -j DROP",
	} {
		if !strings.Contains(policy, want) {
			t.Fatalf("required denial path missing: %q", want)
		}
	}
	for _, want := range []string{"$i == \"link/ether\"", "$i == \"lladdr\"", "$2 == \"from\"", "$3 == guest", "$(i + 1) == uplink"} {
		if !strings.Contains(policy, want) {
			t.Fatalf("uplink discovery missing %q", want)
		}
	}
	if strings.Contains(policy, "docker0") || strings.Contains(policy, "br-*") || strings.Contains(policy, "input tcp dport 35796 accept") {
		t.Fatal("policy retains an unowned bridge or guest peer listener")
	}
}

func TestGuestPolicyRejectsInvalidPeerPort(t *testing.T) {
	for _, port := range []int{0, -1, 65536} {
		if _, err := GuestPolicyScript(port); err == nil {
			t.Fatalf("port %d was accepted", port)
		}
	}
}

func TestGuestPolicyAddsMonitorOnlyHealthAndMetricsWhenEnabled(t *testing.T) {
	policy, err := GuestPolicyScript(QBitTorrentPort, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"ip saddr 10.10.10.20 tcp dport { 9100, 9110 } accept", "ip saddr 10.10.10.20 tcp dport 9110 accept", "-s 10.10.10.20 -p tcp --dport 9110 -j ACCEPT"} {
		if !strings.Contains(policy, required) {
			t.Fatalf("monitor policy missing %q", required)
		}
	}
	if strings.Index(policy, "-s 10.10.10.20 -p tcp --dport 9110 -j ACCEPT") > strings.Index(policy, "-s \"$net\" -j DROP") {
		t.Fatal("monitoring Docker health rule is placed after the private-source drop")
	}
	if strings.Contains(policy, "oifname \"$bridge\" ether saddr \"$gateway_mac\" ip saddr 10.10.10.20 tcp dport { 9110, 9100 }") || strings.Contains(policy, "--dports 9110,9100") {
		t.Fatal("monitor metrics port is incorrectly exposed through Docker forwarding")
	}
	without, err := GuestPolicyScript(QBitTorrentPort)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(without, "10.10.10.20") || strings.Contains(without, "9110") || strings.Contains(without, "9100") {
		t.Fatal("disabled monitoring opened health or metrics ports")
	}
}

func TestGuestPolicyScriptParsesAsShell(t *testing.T) {
	policy, err := GuestPolicyScript(QBitTorrentPort)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "boetticher-arrstack-firewall")
	if err := os.WriteFile(path, []byte(policy), 0700); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("sh", "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("generated policy is not valid shell: %v: %s", err, output)
	}
	if outputPath := os.Getenv("ARRSTACK_POLICY_OUTPUT"); outputPath != "" {
		if err := os.WriteFile(outputPath, []byte(policy), 0700); err != nil {
			t.Fatalf("write requested policy output: %v", err)
		}
	}
}
