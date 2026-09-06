package ansible

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAirVPNReconcilesForwardingAfterActiveTunnelVerification(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "airvpn", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	verified := strings.Index(text, "- name: Require an active AirVPN transit service")
	forwarding := strings.Index(text, "- name: Enable forwarding after AirVPN tunnel verification")
	if verified < 0 || forwarding <= verified {
		t.Fatal("an already-running tunnel must regain forwarding only after verification")
	}
	block := ansibleTaskBlock(text, "Enable forwarding after AirVPN tunnel verification")
	if !strings.Contains(block, "net.ipv4.ip_forward=1") || !strings.Contains(block, "changed_when: true") || !strings.Contains(block, "airvpn_forwarding_state.stdout") {
		t.Fatal("verified AirVPN configuration leaves forwarding disabled")
	}
}

func TestAirVPNPolicyAndDNSActivationAreChangeTriggered(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "airvpn", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "Apply the AirVPN guest kill switch before starting WireGuard") {
		t.Fatal("AirVPN policy is still directly activated outside its systemd owner")
	}
	if strings.Contains(text, "name: boetticher-airvpn-firewall.service\n    enabled: true\n    state: restarted") {
		t.Fatal("AirVPN firewall is still unconditionally restarted")
	}
	if strings.Contains(text, "name: dnsmasq\n    enabled: true\n    state: restarted") {
		t.Fatal("AirVPN dnsmasq is still unconditionally restarted")
	}
	for _, expected := range []string{
		"register: airvpn_policy_install",
		"when: airvpn_policy_install.changed",
		"notify: reload AirVPN firewall policy",
		"notify: restart AirVPN dnsmasq",
		"meta: flush_handlers",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("AirVPN change-triggered lifecycle is missing %q", expected)
		}
	}
	unit, err := os.ReadFile(filepath.Join("..", "..", "images", "airvpn", "runtime", "boetticher-airvpn-firewall.service"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unit), "ExecReload=/usr/sbin/nft -f /etc/nftables.d/airvpn.nft") {
		t.Fatal("AirVPN firewall unit has no native policy reload path")
	}
}
