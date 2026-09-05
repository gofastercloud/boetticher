package ansible

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTailnetPolicyAndHookActivationAreChangeTriggered(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "tailnet-router", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "name: boetticher-tailnet-firewall\n    enabled: true\n    state: restarted") {
		t.Fatal("Tailnet firewall is still unconditionally restarted")
	}
	for _, expected := range []string{
		"register: tailnet_policy_install",
		"when: tailnet_policy_install.changed",
		"notify: reload Tailnet firewall policy",
		"restart tailscaled after Tailnet hook change",
		"meta: flush_handlers",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("Tailnet change-triggered lifecycle is missing %q", expected)
		}
	}
	unit, err := os.ReadFile(filepath.Join("..", "..", "images", "tailnet-router", "runtime", "boetticher-tailnet-firewall.service"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unit), "ExecReload=/usr/sbin/nft -f /etc/nftables.d/tailnet.nft") {
		t.Fatal("Tailnet firewall unit has no native policy reload path")
	}
}
