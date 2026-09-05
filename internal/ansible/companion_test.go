package ansible

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func companionSource(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "kiosk", path))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestAllCompanionTaskFilesParse(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "ansible", "roles", "kiosk", "tasks", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var tasks []map[string]any
		if err := yaml.Unmarshal(data, &tasks); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
}

func TestCompanionNewCredentialBoundary(t *testing.T) {
	credential := companionSource(t, "tasks/credential.yml")
	for _, required := range []string{"not installed_credential.stat.exists", "credential_value | hash('sha256')", "path: /run", "always:", "state: absent", "mode: '0600'", "remote_src: true", "no_log: true"} {
		if !strings.Contains(credential, required) {
			t.Fatalf("credential safety requirement missing: %s", required)
		}
	}
	var tasks []map[string]any
	if err := yaml.Unmarshal([]byte(credential), &tasks); err != nil {
		t.Fatal(err)
	}
	for _, task := range tasks {
		block, ok := task["block"].([]any)
		if !ok {
			continue
		}
		for _, entry := range block {
			m := entry.(map[string]any)
			if m["ansible.builtin.copy"] != nil || m["ansible.builtin.command"] != nil {
				if m["no_log"] != true {
					t.Fatal("credential operation may log private material")
				}
			}
		}
	}
	status := companionSource(t, "templates/boetticher-companion.service.j2")
	if !strings.Contains(status, "LoadCredentialEncrypted=pulse-token:/var/lib/boetticher/credentials/companion-read.cred") {
		t.Fatal("status service missing encrypted token binding")
	}
	deck := companionSource(t, "templates/boetticher-streamdeck.service.j2")
	for _, forbidden := range []string{"LoadCredential", "pulse-token", "AF_INET"} {
		if strings.Contains(deck, forbidden) {
			t.Fatalf("deck has unnecessary credential/network authority: %s", forbidden)
		}
	}
	if !strings.Contains(deck, "DevicePolicy=closed") || !strings.Contains(deck, "User=streamdeck") {
		t.Fatal("USB renderer lost confinement")
	}
	agent := companionSource(t, "templates/pulse-agent.service.j2")
	for _, required := range []string{"LoadCredentialEncrypted=pulse-agent-token:", "companion-agent.cred", "--enable-commands=false", "--enable-proxmox=false", "NoNewPrivileges=true"} {
		if !strings.Contains(agent, required) {
			t.Fatalf("agent lost boundary %s", required)
		}
	}
}

func TestCompanionCleanupFollowsFunctionalCheck(t *testing.T) {
	source := companionSource(t, "tasks/main.yml")
	check := strings.Index(source, "Check enabled Companion functions after startup")
	cleanup := strings.Index(source, "Remove superseded browser identity")
	if check < 0 || cleanup < check {
		t.Fatal("migration cleanup precedes functional check")
	}
	for _, path := range []string{"/home/kiosk/.pki/nssdb", "companion-streamdeck-pulse-token.cred", "companion-streamdeck-pulse-token.sha256", "client.key.pem", "client.crt.pem"} {
		if !strings.Contains(source[cleanup:], path) {
			t.Fatalf("migration omits old credential %s", path)
		}
	}
	disabled := companionSource(t, "tasks/disabled.yml")
	if !strings.Contains(disabled, "companion_optional_unit.stat.exists") || !strings.Contains(disabled, "not (capability.enabled | bool)") {
		t.Fatal("disabled cleanup is not scoped to an existing unselected capability")
	}
}

func TestCompanionKioskIsCredentialFreeAndKeyboardFree(t *testing.T) {
	service := companionSource(t, "templates/pulse-kiosk.service.j2")
	for _, required := range []string{"User=kiosk", "NoNewPrivileges=yes", "ProtectSystem=strict", "CapabilityBoundingSet=", "LIBSEAT_BACKEND=seatd", "WLR_LIBINPUT_NO_DEVICES=1", "Requires=seatd.service", "kiosk-seat", "http://127.0.0.1:8765/"} {
		if !strings.Contains(service, required) {
			t.Fatalf("kiosk missing %s", required)
		}
	}
	for _, forbidden := range []string{"network-online.target", "--no-sandbox", "auto-select-certificate", "load-extension", "X-API-Token", "LoadCredential"} {
		if strings.Contains(service, forbidden) {
			t.Fatalf("kiosk retains %s", forbidden)
		}
	}
}
