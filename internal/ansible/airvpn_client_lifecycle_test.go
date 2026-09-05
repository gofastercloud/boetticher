package ansible

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAirVPNClientActivationIsBootstrapOnlyAndChangeTriggered(t *testing.T) {
	siteData, err := os.ReadFile(filepath.Join("..", "..", "ansible", "site.yml"))
	if err != nil {
		t.Fatal(err)
	}
	siteText := string(siteData)
	if !strings.Contains(siteText, "inventory_hostname in (airvpn_selected_guests | default([]))\n        - boetticher_deploy_phase | default('full') in ['full', 'bootstrap']") {
		t.Fatal("selected-client AirVPN role is not limited to the full/bootstrap foundation")
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "airvpn-client", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "name: boetticher-airvpn-client\n    enabled: true\n    state: restarted") {
		t.Fatal("selected-client AirVPN policy is still unconditionally restarted")
	}
	for _, expected := range []string{"register: airvpn_client_policy_install", "register: airvpn_client_unit_install", "'restarted' if airvpn_client_policy_install.changed or airvpn_client_unit_install.changed"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("selected-client AirVPN lifecycle is missing %q", expected)
		}
	}
}
