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
	if !strings.Contains(block, "net.ipv4.ip_forward=1") {
		t.Fatal("verified AirVPN configuration leaves forwarding disabled")
	}
}
