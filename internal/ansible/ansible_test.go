package ansible

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestGatusRolePreparesConfigDirectoryAndReloadsNginx(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "gatus", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	if !strings.Contains(text, "path: /etc/boetticher/gatus, state: directory") {
		t.Fatal("Gatus role does not create its configuration directory before copying config")
	}
	if !strings.Contains(text, "dest: /etc/nginx/sites-enabled/gatus.conf, state: link") || !strings.Contains(text, "notify: reload nginx") {
		t.Fatal("Gatus role does not notify nginx after enabling its site")
	}
}

func TestGatusRoleInstallsBoetticherRootTrustForEndpointChecks(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "gatus", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, required := range []string{
		"dest: /usr/local/share/ca-certificates/boetticher-gatus.crt",
		"content: \"{{ step_ca_root_cert_pem }}\"",
		"ansible.builtin.command: update-ca-certificates",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("Gatus role is missing endpoint trust setup %q", required)
		}
	}
}

func TestAirVPNRoleCreatesRuntimeDirectoryBeforeSystemdStart(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "airvpn", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	directory := strings.Index(text, "path: /run/boetticher\n")
	start := strings.Index(text, "name: Enable and start the AirVPN transit service")
	if directory < 0 || start < 0 || directory > start {
		t.Fatal("AirVPN role does not create /run/boetticher before systemd namespacing")
	}
}

func TestGatusRoleUsesEndpointOwnedSmallstepCertificate(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "gatus", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, required := range []string{
		"path: /var/lib/boetticher/identity/tls, state: directory",
		"include_tasks: ../../tasks/step-ca-endpoint.yml",
		"step_ca_endpoint_subject: \"gatus.{{ domain }}\"",
		"step_ca_endpoint_key_path: /var/lib/boetticher/identity/tls/gatus.key.pem",
		"step_ca_endpoint_reload_service: nginx",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("Gatus role is missing endpoint-owned certificate contract %q", required)
		}
	}
	for _, forbidden := range []string{"gatus_server_cert_pem", "gatus.csr.pem", "ansible.builtin.fetch:"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("Gatus role retains controller certificate exchange %q", forbidden)
		}
	}
}

func TestPrinterRoleUsesSmallstepServerCertificateAndRetainsClientMTLS(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "printer", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, required := range []string{
		"include_tasks: ../../tasks/step-ca-endpoint.yml",
		"step_ca_endpoint_subject: \"octoprint.{{ domain }}\"",
		"step_ca_endpoint_key_path: /var/lib/boetticher/identity/tls/octoprint.key.pem",
		"ssl_verify_client on;",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("Printer TLS contract is missing %q", required)
		}
	}
	for _, forbidden := range []string{"octoprint_server_cert_pem", "octoprint.csr.pem", "ansible.builtin.fetch:"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("Printer role retains controller server-certificate exchange %q", forbidden)
		}
	}
}

func TestArrRoleUsesSmallstepServerCertificateAndRetainsClientMTLS(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "arr", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, required := range []string{
		"include_tasks: ../../tasks/step-ca-endpoint.yml",
		"step_ca_endpoint_subject: \"sonarr.{{ domain }}\"",
		"step_ca_endpoint_key_path: /var/lib/boetticher/identity/tls/arr.key.pem",
		"ssl_verify_client on;",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("arr TLS contract is missing %q", required)
		}
	}
	for _, forbidden := range []string{"arr_server_cert_pem", "arr.csr.pem", "ansible.builtin.fetch:"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("arr role retains controller server-certificate exchange %q", forbidden)
		}
	}
}

func TestARRRoleUsesBoundedGuestLocalConfiguration(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "arr", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"boetticher-arr-configure, check", "boetticher-arr-configure, prepare", "boetticher-arr-configure, wire", "state: stopped", "readarr.service", "loop: [sonarr, radarr, lidarr, prowlarr, qbittorrent]"} {
		if !strings.Contains(string(contents), required) {
			t.Fatalf("ARR lifecycle missing %q", required)
		}
	}
	for _, forbidden := range []string{"<ApiKey>", "ansible.builtin.slurp:", "ansible.builtin.fetch:", "apt:"} {
		if strings.Contains(string(contents), forbidden) {
			t.Fatalf("ARR role crosses guest-local artifact boundary: %q", forbidden)
		}
	}
}

func TestCompanionStreamDeckUsesDirectUSBAndScopedRuntimeFiles(t *testing.T) {
	playbook, err := os.ReadFile(filepath.Join("..", "..", "ansible", "companion.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(playbook), "    - kiosk") {
		t.Fatal("companion playbook does not use the companion role")
	}
	tasks, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "kiosk", "tasks", "streamdeck.yml"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "kiosk", "templates", "boetticher-streamdeck.service.j2"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(tasks) + string(service)
	for _, expected := range []string{
		"name: streamdeck",
		"dest: /usr/local/libexec/boetticher-streamdeck",
		"dest: /etc/boetticher/streamdeck.json",
		"ATTR{idVendor}==\"0fd9\", ATTR{idProduct}==\"006d\"",
		"SupplementaryGroups=companion",
		"RestrictAddressFamilies=AF_UNIX",
		"DevicePolicy=closed",
		"DeviceAllow=char-usb_device rw",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("companion StreamDeck contract is missing %q", expected)
		}
	}
	if strings.Contains(text, "/dev/bus/usb/*/*") || strings.Contains(text, "ansible_user_id: root") {
		t.Fatal("companion StreamDeck role contains broad USB or root-service handling")
	}
	// The approved local-dashboard design moves credential ownership to the
	// status collector. TestCompanionNewCredentialBoundary verifies its
	// encrypted delivery and drift guard; the USB process must have no token.
	if strings.Contains(string(service), "LoadCredential") || strings.Contains(string(service), "pulse-token") {
		t.Fatal("StreamDeck must consume local status without Pulse credentials")
	}
}

func TestCompanionCapabilityPackagesAndCleanupAreIndependent(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "kiosk", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	displayPackages := ansibleTaskBlock(text, "Configure the Cage display")
	if displayPackages == "" || !strings.Contains(displayPackages, "when: kiosk_display_enabled | bool") {
		t.Fatal("display-only companion packages are not capability-gated")
	}
	packages := companionSource(t, "tasks/display.yml")
	if !strings.Contains(packages, "cage, chromium, seatd") {
		t.Fatal("display-only companion package set is incomplete")
	}
	disabled := companionSource(t, "tasks/disabled.yml")
	if !strings.Contains(disabled, "companion_optional_unit.stat.exists") || !strings.Contains(disabled, "not (capability.enabled | bool)") {
		t.Fatal("disabled companion cleanup can attempt to stop units that were never installed")
	}
	for _, expected := range []string{
		"Configure the Pulse host agent",
		"Configure the StreamDeck",
		"Configure Blinkt",
		"Remove superseded browser identity and telemetry assets after acceptance",
		"/home/kiosk/.pki/nssdb",
		"/var/lib/boetticher/credentials/companion-streamdeck-pulse-token.cred",
		"ansible.builtin.meta: flush_handlers",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("disabled companion cleanup is missing %q", expected)
		}
	}
}

func TestPhaseVariablesExposeOnlySafeDeploymentPhaseMetadata(t *testing.T) {
	data, err := phaseVariables([]byte(`{"example":"value"}`), PhaseBootstrap)
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]any
	if err := json.Unmarshal(data, &values); err != nil {
		t.Fatal(err)
	}
	if values["boetticher_deploy_phase"] != PhaseBootstrap {
		t.Fatalf("phase metadata = %v, want %q", values["boetticher_deploy_phase"], PhaseBootstrap)
	}
	if values["example"] != "value" {
		t.Fatalf("phase variable rewrite lost existing value: %v", values)
	}
	if _, err := phaseVariables([]byte(`{}`), "unexpected"); err == nil {
		t.Fatal("unsupported phase was accepted")
	}
	if _, err := phaseVariables([]byte(`{}`), PhaseHealth); err != nil {
		t.Fatalf("health phase was rejected: %v", err)
	}
}

func TestServicePhaseSkipsNetworkOnlyRoles(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "ansible", "site.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, expected := range []string{
		"- role: dns\n      when:\n        - inventory_hostname in groups.get('dns', [])\n        - boetticher_deploy_phase | default('full') in ['full', 'bootstrap']",
		"- role: firewall\n      when:\n        - inventory_hostname in groups.get('firewall', [])\n        - boetticher_deploy_phase | default('full') in ['full', 'bootstrap']",
		"- role: firewall\n      when:\n        - inventory_hostname in groups.get('firewall', [])\n        - boetticher_deploy_phase | default('full') in ['full', 'bootstrap']\n        - not (boetticher_skip_firewall | default(false) | bool)",
		"- role: tailnet-router\n      when:\n        - inventory_hostname in groups.get('tailnet-router', [])\n        - boetticher_deploy_phase | default('full') in ['full', 'bootstrap']",
		"- role: chrony\n      when: boetticher_deploy_phase | default('full') in ['full', 'bootstrap']",
		"- role: usb-export-host\n      when: boetticher_deploy_phase | default('full') in ['full', 'bootstrap']",
		"- role: network-probe-host\n      when: boetticher_deploy_phase | default('full') in ['full', 'bootstrap']",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("site playbook is missing service-phase guard block %q", expected)
		}
	}
}

func TestFirewallRoleRunsBeforeBaseOnManagedPlay(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "ansible", "site.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	firewallIndex := strings.Index(text, "- role: firewall")
	baseIndex := strings.Index(text, "    - base")
	if firewallIndex < 0 || baseIndex < 0 || firewallIndex > baseIndex {
		t.Fatal("firewall role must run before base so a replacement gateway enables forwarding before delegated certificate work")
	}
}

func TestAirVPNRoleRunsBeforeBaseAndSelectedClients(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "ansible", "site.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	baseIndex := strings.Index(text, "    - base")
	airVPNIndex := strings.Index(text, "    - role: airvpn\n")
	clientIndex := strings.Index(text, "    - role: airvpn-client\n")
	if baseIndex < 0 || airVPNIndex < 0 || clientIndex < 0 || airVPNIndex > baseIndex || baseIndex > clientIndex {
		t.Fatal("AirVPN role must run before base logging setup and selected-client policy")
	}
	if !strings.Contains(text[airVPNIndex:], "boetticher_deploy_phase | default('full') in ['full', 'bootstrap']") {
		t.Fatal("AirVPN role must run only in the early full/bootstrap foundation pass")
	}
	if strings.Contains(text[airVPNIndex:], "boetticher_deploy_phase | default('full') in ['full', 'bootstrap', 'services']") {
		t.Fatal("AirVPN role must not run again during the services phase")
	}
	if strings.Count(text, "    - role: airvpn\n") != 1 || !strings.Contains(text[:airVPNIndex], "hosts: airvpn") {
		t.Fatal("AirVPN role must run exactly once in the early AirVPN host play")
	}
	if strings.Contains(text[:baseIndex], "    - role: chrony\n") {
		t.Fatal("Chrony must not start before the base role applies the unprivileged appliance options")
	}
}

func TestAirVPNRoleRequiresControllerCredentialBeforeStartup(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "airvpn", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	installIndex := strings.Index(text, "Require the controller-installed AirVPN credential and unit binding")
	startIndex := strings.Index(text, "Enable and start the AirVPN transit service")
	if installIndex < 0 || startIndex < 0 || installIndex > startIndex {
		t.Fatal("AirVPN controller credential check must precede the transit service startup")
	}
	for _, required := range []string{
		"/var/lib/boetticher/credentials/airvpn-wireguard-config.cred",
		"/etc/systemd/system/boetticher-airvpn.service.d/boetticher-credentials.conf",
		"retries: 12",
		"delay: 5",
		"until: airvpn_interface.rc == 0",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("AirVPN startup credential projection is missing %q", required)
		}
	}
}

func TestStableBaseTasksSkipServicesButFinalTasksRemain(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "base", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, name := range []string{
		"Install base packages",
		"Remove labadmin from the sudo group",
		"Configure Chrony for unprivileged appliances",
		"Allow Chrony startup without kernel clock control",
		"Install Chrony startup override",
		"Disable the restricted Chrony service in appliances",
		"Configure appliances to use the platform DNS pair",
		"Write bounded local journald configuration",
		"Issue and renew the endpoint-local logging client certificate from Smallstep",
		"Install the asynchronous journal-upload configuration skeleton",
		"Install bounded journal-upload retry policy",
	} {
		block := ansibleTaskBlock(text, name)
		if block == "" || !strings.Contains(block, "boetticher_deploy_phase | default('full') in ['full', 'bootstrap']") {
			t.Fatalf("stable base task %q is not guarded from the services phase", name)
		}
	}
	for _, name := range []string{
		"Create declared systemd credential drop-in directories",
		"Install declared systemd credential drop-ins",
	} {
		block := ansibleTaskBlock(text, name)
		if block == "" || !strings.Contains(block, "boetticher_deploy_phase | default('full') != 'services'") {
			t.Fatalf("runtime base task %q is not available outside the services phase", name)
		}
	}
	for _, name := range []string{"Enable asynchronous journal upload after endpoint certificate installation"} {
		block := ansibleTaskBlock(text, name)
		if block == "" || strings.Contains(block, "boetticher_deploy_phase | default('full') != 'services'") {
			t.Fatalf("final base task %q was incorrectly skipped from the services phase", name)
		}
	}
}

func TestFirewallInterfaceTemplatesUseOneLiveDriftProbe(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "firewall", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, expected := range []string{
		"Check managed gateway interface configuration for drift",
		"firewall_interface_config_digests[item.name].link",
		"firewall_interface_config_digests[item.name].network",
		"firewall_interface_state.rc != 0",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("firewall role is missing live interface drift guard %q", expected)
		}
	}
}

func TestFirewallRulesetTransferIsGatedByLiveContentDigest(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "firewall", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, expected := range []string{
		"firewall_ruleset_sha256 is match('^[0-9a-f]{64}$')",
		"Check the managed gateway nftables ruleset for drift",
		"sha256sum \"$path\"",
		"firewall_ruleset_state.rc != 0",
		"Apply the validated ruleset before enabling forwarding",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("firewall role is missing content-addressed ruleset guard %q", expected)
		}
	}
}

func ansibleTaskBlock(text, name string) string {
	start := strings.Index(text, "- name: "+name)
	if start < 0 {
		return ""
	}
	rest := text[start+len("- name: "):]
	if next := strings.Index(rest, "\n- name:"); next >= 0 {
		return text[start : start+len("- name: ")+next]
	}
	return text[start:]
}

func TestGatusServiceUsesSupportedConfigEnvironment(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "images", "gatus", "runtime", "gatus.service"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	if !strings.Contains(text, "Environment=GATUS_CONFIG_PATH=/etc/boetticher/gatus/config.yaml") {
		t.Fatal("Gatus service does not set the supported configuration path environment")
	}
	if strings.Contains(text, "--config-path") {
		t.Fatal("Gatus service invokes an unsupported config-path argument")
	}
}

func TestInventoryContainsBastionAndFixedAddresses(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	first, err := Inventory(site)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Inventory(site)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("inventory was not deterministic")
	}
	for _, expected := range []string{
		"lab-proxmox-01 ansible_host=10.10.99.5",
		"lab-dns-01 ansible_host=10.10.10.10",
		"ansible_remote_tmp=/var/lib/boetticher/ansible",
		"[managed:children]",
	} {
		if !strings.Contains(first, expected) {
			t.Errorf("inventory missing %q", expected)
		}
	}
	if strings.Contains(first, "ansible_ssh_common_args") {
		t.Fatal("inventory duplicated the site-local SSH transport policy")
	}
}

func TestInventoryUsesBootstrapAddressForProxmoxTransport(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	site.BootstrapAddress = "192.0.2.5"
	inventory, err := Inventory(site)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(inventory, "lab-proxmox-01 ansible_host=192.0.2.5") {
		t.Fatalf("Proxmox inventory did not use bootstrap address:\n%s", inventory)
	}
	if strings.Contains(inventory, "lab-proxmox-01 ansible_host=10.10.99.5") {
		t.Fatal("Proxmox inventory used the internal management address for controller transport")
	}
}

func TestMonitoringAgentTargetsAreTagDrivenAndDefaultToProxmox(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	got := MonitoringAgentTargets(site)
	if len(got) != 1 || got[0] != model.LogicalProxmoxIdentity {
		t.Fatalf("default monitoring-agent targets = %v, want only %q", got, model.LogicalProxmoxIdentity)
	}
	for _, component := range site.PlatformComponents() {
		if component.Name == "lab-monitor-01" || component.Name == "lab-dns-01" {
			for _, tag := range component.Tags {
				if tag == model.TagMonitoringAgent {
					t.Fatalf("untargeted component %s carries the monitoring-agent tag", component.Name)
				}
			}
		}
	}
	for index := range site.Components {
		if site.Components[index].Name == "lab-monitor-01" {
			site.Components[index].Tags = append(site.Components[index].Tags, model.TagMonitoringAgent)
		}
	}
	got = MonitoringAgentTargets(site)
	if len(got) != 2 || got[0] != "lab-monitor-01" || got[1] != model.LogicalProxmoxIdentity {
		t.Fatalf("tagged monitoring-agent targets = %v, want sorted Proxmox and monitor targets", got)
	}
	site.Components = append(site.Components, model.Component{
		Name: "user-vm-501", VMID: 501, Hostname: "user-vm-501", Zone: "SANDBOX", Address: "10.10.40.1",
		Role: "user workload", Tags: []string{model.TagMonitoringAgent}, ProductOwned: false,
	})
	if err := site.Validate(); err != nil {
		t.Fatalf("valid user workload with monitoring-agent tag was rejected: %v", err)
	}
	got = MonitoringAgentTargets(site)
	if len(got) != 2 || got[0] != "lab-monitor-01" || got[1] != model.LogicalProxmoxIdentity {
		t.Fatalf("user workload with monitoring-agent tag was selected: %v", got)
	}
}

func TestAnsibleVariablesPinPulseHostAgentAndExposeNoSecret(t *testing.T) {
	data, err := Variables(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, expected := range []string{
		`"proxmox_management_address": "10.10.99.5"`,
		"\"pulse_agent_targets\": [\n    \"lab-proxmox-01\"",
		`"pulse_agent_version": "6.4.1"`,
		`"pulse_agent_release_url": "https://github.com/rcourtman/Pulse/releases/download/v6.4.1/pulse-agent-linux-amd64"`,
		`"pulse_agent_release_sha256": "974708439f052136cac2a334ad790bf9da12b3f1c8e758ebe7bc0a8d2a505ce9"`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("Ansible variables missing Pulse host-agent contract %q", expected)
		}
	}
	if strings.Contains(text, "agent-token") || strings.Contains(text, "pulse_agent_token") {
		t.Fatal("Ansible variables contain a Pulse agent credential")
	}
}

func TestBaseRoleInstallsPulseAgentOnlyForEnabledTaggedTargets(t *testing.T) {
	tasks, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "base", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "base", "templates", "pulse-agent.service.j2"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(tasks) + "\n" + string(service)
	for _, expected := range []string{
		"pulse_agent_install_enabled",
		"pulse_agent_targets",
		"pulse-agent.service",
		"pulse_agent_release_url",
		"pulse_agent_release_sha256",
		"lm-sensors",
		"smartmontools",
		"--enable-host=true",
		"--enable-proxmox=false",
		"--enable-docker=false",
		"--enable-kubernetes=false",
		"--enable-commands=false",
		"--disable-auto-update",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("Pulse host-agent setup missing %q", expected)
		}
	}
}

func TestUSBExportRoleCreatesInstallRootAndPreservesStaticSlots(t *testing.T) {
	tasks, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "usb-export-host", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	reconciler, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "usb-export-host", "files", "boetticher-usb-export"))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"Create Core USB install directory",
		"path: /usr/lib/boetticher",
	} {
		if !strings.Contains(string(tasks), expected) {
			t.Fatalf("USB export role missing %q", expected)
		}
	}
	for _, expected := range []string{
		"static_slots",
		"if argv == [\"--all\"] and not paths: return",
		"if slot not in managed_slots and slot not in static_slots",
	} {
		if !strings.Contains(string(reconciler), expected) {
			t.Fatalf("USB export reconciler missing %q", expected)
		}
	}
}

func TestAIOpsServiceAllowsDeclaredDNSResolvers(t *testing.T) {
	service, err := os.ReadFile(filepath.Join("..", "..", "images", "aiops", "runtime", "boetticher-aiops.service"))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"LoadCredentialEncrypted=webhook-secret:/var/lib/boetticher/credentials/aiops-webhook-secret.cred",
		"LoadCredentialEncrypted=pulse-read-token:/var/lib/boetticher/credentials/aiops-pulse-read-token.cred",
		"LoadCredentialEncrypted=pulse-note-token:/var/lib/boetticher/credentials/aiops-pulse-note-token.cred",
		"IPAddressAllow=10.10.10.10",
		"IPAddressAllow=10.10.10.11",
	} {
		if !strings.Contains(string(service), expected) {
			t.Fatalf("AIOps service missing %q", expected)
		}
	}
}

func TestHolmesServiceUsesPinnedConfigDirectoryContract(t *testing.T) {
	service, err := os.ReadFile(filepath.Join("..", "..", "images", "aiops", "runtime", "holmes.service"))
	if err != nil {
		t.Fatal(err)
	}
	build, err := os.ReadFile(filepath.Join("..", "..", "scripts", "build-images.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(service), "HOLMES_CONFIGPATH_DIR=/etc/boetticher-aiops") {
		t.Fatal("Holmes service does not configure the pinned HolmesGPT config directory contract")
	}
	if strings.Contains(string(service), "HOLMES_CONFIG_PATH=") {
		t.Fatal("Holmes service uses an unsupported config-path variable")
	}
	if !strings.Contains(string(build), "images/aiops/runtime/holmes.yaml \"$rootfs/etc/boetticher-aiops/config.yaml\"") {
		t.Fatal("AIOps image does not install its config at HolmesGPT's default filename")
	}
}

func TestMonitorFrontendUsesTokensForScopedReadRoutes(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "monitor", "templates", "pulse-loopback.conf.j2"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "ssl_verify_client optional") || !strings.Contains(text, "scoped API tokens") {
		t.Fatal("monitor frontend does not distinguish mTLS UI and token-authenticated read routes")
	}
	if strings.Contains(text, "ssl_verify_client off") {
		t.Fatal("monitor frontend uses an invalid location-scoped client verification directive")
	}
	if !strings.Contains(text, "location ^~ /api/agents/") {
		t.Fatal("monitor frontend does not proxy the supported Pulse agent routes")
	}
	if got := strings.Count(text, "if ($ssl_client_verify != SUCCESS) { return 403; }"); got != 1 {
		t.Fatalf("monitor frontend mTLS guards = %d, want only the browser catch-all", got)
	}
	for _, route := range []string{"location = /api/health", "location = /api/state/summary", "location = /api/resources"} {
		start := strings.Index(text, route)
		if start < 0 {
			t.Fatalf("monitor frontend omitted %s", route)
		}
		end := strings.Index(text[start:], "\n    }")
		if end < 0 {
			t.Fatalf("monitor frontend has unterminated %s", route)
		}
		block := text[start : start+end]
		if strings.Contains(block, "$ssl_client_verify") || strings.Contains(block, "$ssl_client_s_dn") {
			t.Fatalf("token route %s still depends on client certificate identity: %s", route, block)
		}
	}
	if !strings.Contains(text, `CN=aiops-pulse-(?:read|note)`) {
		t.Fatal("monitor catch-all does not deny the AIOps identities outside their exact routes")
	}
}

func TestGeneratedSSHConfigPathIsBoundToInventoryProjection(t *testing.T) {
	got := generatedSSHConfigPath("/tmp/site/generated/ansible/inventory.ini")
	if got != "/tmp/site/generated/ssh/boetticher.conf" {
		t.Fatalf("generated SSH config path = %q", got)
	}
}

func TestAnsibleStrategyAllowsParallelConvergenceOnlyAfterFoundation(t *testing.T) {
	t.Setenv("ANSIBLE_STRATEGY", "free")
	for _, test := range []struct {
		phase string
		want  string
	}{
		{phase: PhaseFull, want: defaultAnsibleStrategy},
		{phase: PhaseBootstrap, want: defaultAnsibleStrategy},
		{phase: PhaseServices, want: defaultAnsibleStrategy},
		{phase: PhaseHealth, want: defaultAnsibleStrategy},
	} {
		environment := ansibleEnvironment("ansible/site.yml", "", test.phase)
		prefix := "ANSIBLE_STRATEGY="
		got := ""
		for _, entry := range environment {
			if strings.HasPrefix(entry, prefix) {
				got = strings.TrimPrefix(entry, prefix)
				break
			}
		}
		if got != test.want {
			t.Fatalf("ANSIBLE_STRATEGY for phase %q = %q, want %q", test.phase, got, test.want)
		}
	}
}

func TestAnsibleEnvironmentClearsAmbientConfiguration(t *testing.T) {
	for key, value := range map[string]string{
		"ANSIBLE_CONFIG":           "/tmp/attacker.cfg",
		"ANSIBLE_FORKS":            "999",
		"ANSIBLE_COLLECTIONS_PATH": "/tmp/collections",
		"PYTHONPATH":               "/tmp/python",
		"VIRTUAL_ENV":              "/tmp/venv",
	} {
		t.Setenv(key, value)
	}
	environment := ansibleEnvironment("ansible/site.yml", "", PhaseFull)
	values := make(map[string]string, len(environment))
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			values[key] = value
		}
	}
	if values["ANSIBLE_CONFIG"] != "/dev/null.cfg" || values["ANSIBLE_FORKS"] != defaultAnsibleForks || values["PYTHONNOUSERSITE"] != "1" || values["PATH"] != safeControllerPath {
		t.Fatalf("Ansible environment did not apply the bounded controller contract: %#v", values)
	}
	for _, key := range []string{"ANSIBLE_COLLECTIONS_PATH", "PYTHONPATH", "VIRTUAL_ENV"} {
		if _, ok := values[key]; ok {
			t.Fatalf("ambient Ansible/Python setting %s survived environment filtering", key)
		}
	}
}

func TestAnsibleProcessGroupStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := runInProcessGroup(ctx, exec.Command("sh", "-c", "sleep 30"))
	if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("cancelled Ansible process returned %v", err)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("cancelled Ansible process group took %s to terminate", elapsed)
	}
}

func TestRunUsesAnsibleStdinPathForExtraVars(t *testing.T) {
	tempDir := t.TempDir()
	inventoryPath := filepath.Join(tempDir, "site", "generated", "ansible", "inventory.ini")
	sshConfigPath := filepath.Join(tempDir, "site", "generated", "ssh", "boetticher.conf")
	if err := os.MkdirAll(filepath.Dir(sshConfigPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sshConfigPath, []byte("Host lab-fw-01\n    HostName 192.0.2.10\n"), 0600); err != nil {
		t.Fatal(err)
	}
	argsPath := filepath.Join(tempDir, "args")
	forksPath := filepath.Join(tempDir, "forks")
	inputPath := filepath.Join(tempDir, "input")
	scriptPath := filepath.Join(tempDir, "ansible-playbook")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$BOETTICHER_TEST_ANSIBLE_ARGS_FILE\"\nprintf '%s' \"$ANSIBLE_FORKS\" > \"$BOETTICHER_TEST_ANSIBLE_FORKS_FILE\"\ncat > \"$BOETTICHER_TEST_ANSIBLE_INPUT_FILE\"\nif [ -n \"$BOETTICHER_ANSIBLE_TIMING_FILE\" ]; then printf '%s\\n' '{\"host\":\"lab-fw-01\",\"task\":\"fake task\",\"path\":\"fake.yml:1\",\"status\":\"ok\",\"duration_ms\":3,\"changed\":false,\"markers\":[\"dns-metadata-drift:servers.lab.home.arpa:ALLOW-DNSUPDATE-FROM:20:1:27ee1412f884f2f2:20:27ee1412\"]}' '{\"event\":\"task_batch\",\"task\":\"fake batch\",\"path\":\"fake.yml:2\",\"duration_ms\":7}' >> \"$BOETTICHER_ANSIBLE_TIMING_FILE\"; fi\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	previousFinder := findAnsiblePlaybook
	findAnsiblePlaybook = func() (string, error) { return scriptPath, nil }
	t.Cleanup(func() { findAnsiblePlaybook = previousFinder })
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("BOETTICHER_TEST_ANSIBLE_ARGS_FILE", argsPath)
	t.Setenv("BOETTICHER_TEST_ANSIBLE_FORKS_FILE", forksPath)
	t.Setenv("BOETTICHER_TEST_ANSIBLE_INPUT_FILE", inputPath)
	previousForks, hadForks := os.LookupEnv("ANSIBLE_FORKS")
	if err := os.Unsetenv("ANSIBLE_FORKS"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if hadForks {
			_ = os.Setenv("ANSIBLE_FORKS", previousForks)
		} else {
			_ = os.Unsetenv("ANSIBLE_FORKS")
		}
	})

	result, err := run(context.Background(), filepath.Join("..", "..", "ansible", "site.yml"), inventoryPath, []byte("{}"), "lab-fw-01", PhaseFull, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.TaskTimings) != 1 || result.TaskTimings[0].Task != "fake task" {
		t.Fatalf("Ansible task timings = %+v, want one fake task timing", result.TaskTimings)
	}
	if len(result.TaskTimings[0].Markers) != 1 || result.TaskTimings[0].Markers[0] != "dns-metadata-drift:servers.lab.home.arpa:ALLOW-DNSUPDATE-FROM:20:1:27ee1412f884f2f2:20:27ee1412" {
		t.Fatalf("Ansible task markers = %+v, want the safe DNS observation marker", result.TaskTimings[0].Markers)
	}
	if len(result.TaskBatchTimings) != 1 || result.TaskBatchTimings[0].Task != "fake batch" || result.TaskBatchTimings[0].DurationMS != 7 {
		t.Fatalf("Ansible task batch timings = %+v, want one fake batch timing", result.TaskBatchTimings)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(args)
	if !strings.Contains(text, "--extra-vars\n@/dev/stdin\n") {
		t.Fatalf("Ansible did not receive the supported stdin path:\n%s", text)
	}
	if strings.Contains(text, "@-\n") {
		t.Fatalf("Ansible received the unsupported stdin filename:\n%s", text)
	}
	forks, err := os.ReadFile(forksPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(forks) != defaultAnsibleForks {
		t.Fatalf("Ansible fork default = %q, want %q", forks, defaultAnsibleForks)
	}
	input, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(input), `"boetticher_deploy_phase": "full"`) {
		t.Fatalf("Ansible variables did not contain the deployment phase: %s", input)
	}
}

func TestRunWithIdentityUsesAndCleansTemporarySSHAgent(t *testing.T) {
	tempDir := t.TempDir()
	inventoryPath := filepath.Join(tempDir, "site", "generated", "ansible", "inventory.ini")
	sshConfigPath := filepath.Join(tempDir, "site", "generated", "ssh", "boetticher.conf")
	if err := os.MkdirAll(filepath.Dir(sshConfigPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sshConfigPath, []byte("Host lab-fw-01\n    HostName 192.0.2.10\n"), 0600); err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(tempDir, "identity")
	stopPath := filepath.Join(tempDir, "agent-stopped")
	argsPath := filepath.Join(tempDir, "ansible-args")
	if err := os.WriteFile(filepath.Join(tempDir, "ssh-agent"), []byte("#!/bin/sh\nif [ \"$1\" = \"-s\" ]; then printf 'SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\\nSSH_AGENT_PID=4242; export SSH_AGENT_PID;\\n' \"$BOETTICHER_TEST_AGENT_SOCKET\"; else : > \"$BOETTICHER_TEST_AGENT_STOPPED\"; fi\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "ssh-add"), []byte("#!/bin/sh\ncat > \"$BOETTICHER_TEST_AGENT_IDENTITY\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "ansible-playbook"), []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$BOETTICHER_TEST_ANSIBLE_ARGS\"\ncat >/dev/null\nprintf '%s\\n' 'ok changed=0 unreachable=0 failed=0'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ansiblePath := filepath.Join(tempDir, "ansible-playbook")
	previousFinder := findAnsiblePlaybook
	findAnsiblePlaybook = func() (string, error) { return ansiblePath, nil }
	previousAgent, previousAdd := sshAgentExecutable, sshAddExecutable
	sshAgentExecutable, sshAddExecutable = filepath.Join(tempDir, "ssh-agent"), filepath.Join(tempDir, "ssh-add")
	t.Cleanup(func() {
		findAnsiblePlaybook = previousFinder
		sshAgentExecutable, sshAddExecutable = previousAgent, previousAdd
	})
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("BOETTICHER_TEST_AGENT_SOCKET", filepath.Join(tempDir, "agent.sock"))
	t.Setenv("BOETTICHER_TEST_AGENT_IDENTITY", identityPath)
	t.Setenv("BOETTICHER_TEST_AGENT_STOPPED", stopPath)
	t.Setenv("BOETTICHER_TEST_ANSIBLE_ARGS", argsPath)
	if _, err := run(context.Background(), filepath.Join("..", "..", "ansible", "site.yml"), inventoryPath, []byte("{}"), "lab-fw-01", PhaseFull, []byte("temporary private key")); err != nil {
		t.Fatal(err)
	}
	identity, err := os.ReadFile(identityPath)
	if err != nil || string(identity) != "temporary private key" {
		t.Fatalf("temporary identity was not passed to ssh-add over stdin: err=%v data=%q", err, identity)
	}
	if _, err := os.Stat(stopPath); err != nil {
		t.Fatalf("temporary ssh-agent was not stopped: %v", err)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(args), "-o IdentitiesOnly=no -o ControlMaster=no -o ControlPath=none") || strings.Contains(string(args), "temporary private key") {
		t.Fatalf("Ansible arguments did not select the temporary agent without exposing key material: %s", args)
	}
}

func TestStartTemporarySSHAgentCleansUpAfterIdentityLoadFailure(t *testing.T) {
	tempDir := t.TempDir()
	stopped := filepath.Join(tempDir, "stopped")
	if err := os.WriteFile(filepath.Join(tempDir, "ssh-agent"), []byte("#!/bin/sh\nif [ \"$1\" = \"-s\" ]; then printf 'SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\\nSSH_AGENT_PID=4242; export SSH_AGENT_PID;\\n' \"$BOETTICHER_TEST_AGENT_SOCKET\"; else : > \"$BOETTICHER_TEST_AGENT_STOPPED\"; fi\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "ssh-add"), []byte("#!/bin/sh\nprintf '%s\\n' 'rejected' >&2\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	previousAgent, previousAdd := sshAgentExecutable, sshAddExecutable
	sshAgentExecutable, sshAddExecutable = filepath.Join(tempDir, "ssh-agent"), filepath.Join(tempDir, "ssh-add")
	t.Cleanup(func() { sshAgentExecutable, sshAddExecutable = previousAgent, previousAdd })
	t.Setenv("BOETTICHER_TEST_AGENT_SOCKET", filepath.Join(tempDir, "agent.sock"))
	t.Setenv("BOETTICHER_TEST_AGENT_STOPPED", stopped)
	if _, _, err := startTemporarySSHAgent([]byte("temporary identity")); err == nil {
		t.Fatal("identity-load failure was accepted")
	}
	if _, err := os.Stat(stopped); err != nil {
		t.Fatalf("temporary agent was not cleaned up after identity-load failure: %v", err)
	}
}

func TestFailureDiagnosticKeepsOnlyBoundedErrorLines(t *testing.T) {
	output := []byte("TASK [secret task] ***\nchanged: [host]\nfatal: [host]: FAILED! => {\"msg\":\"failed\"}\nPLAY RECAP ***\nhost : ok=1 unreachable=0 failed=1\n")
	got := failureDiagnostic(output)
	if !strings.Contains(got, "fatal: [host]") || !strings.Contains(got, "unreachable=0") {
		t.Fatalf("diagnostic omitted failure context: %q", got)
	}
	if strings.Contains(got, "secret task") || strings.Contains(got, "changed:") {
		t.Fatalf("diagnostic included non-error task output: %q", got)
	}
}

func TestBoundedOutputRetainsOnlyBoundedPrefixAndSuffix(t *testing.T) {
	var output boundedOutput
	if _, err := output.Write(bytes.Repeat([]byte{'x'}, maxAnsibleOutputBytes*3)); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Write([]byte("fatal: retained suffix")); err != nil {
		t.Fatal(err)
	}
	data := output.Bytes()
	if len(data) > maxAnsibleOutputBytes+len("\n[output truncated]\n") || !bytes.Contains(data, []byte("fatal: retained suffix")) {
		t.Fatalf("bounded output was not retained safely: len=%d", len(data))
	}
}

func TestBoundedOutputRetainsDiagnosticOutsideWindow(t *testing.T) {
	var output boundedOutput
	if _, err := output.Write([]byte("prefix\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Write(bytes.Repeat([]byte{'x'}, maxAnsibleOutputBytes*3)); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Write([]byte("fatal: [lab-tailnet-01]: FAILED! => {\"msg\":\"runtime failed\"}\n")); err != nil {
		t.Fatal(err)
	}
	if got := failureDiagnosticWithSupplement(output.Bytes(), output.DiagnosticBytes()); !strings.Contains(got, "lab-tailnet-01") {
		t.Fatalf("diagnostic omitted error outside bounded output window: %q", got)
	}
}

func TestLimitedRunRejectsShellSyntaxInInventoryIdentity(t *testing.T) {
	for _, value := range []string{"lab-fw-01", "lab_dns_01", "lab.fw"} {
		if !safeInventoryIdentity(value) {
			t.Fatalf("safe inventory identity %q was rejected", value)
		}
	}
	for _, value := range []string{"lab-fw-01;rm", "lab-fw-01 --limit all", ""} {
		if safeInventoryIdentity(value) {
			t.Fatalf("unsafe inventory identity %q was accepted", value)
		}
	}
}

func TestMonitoringApplianceUsesImageProvidedPulseRuntime(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "monitor", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "Require an immutable monitoring appliance artifact") {
		t.Fatal("monitoring does not require an immutable appliance artifact")
	}
	for _, expected := range []string{"/opt/pulse/bin/pulse --version", "path: /var/lib/pulse", "- pulse", "- nginx", "pulse-loopback.conf.j2"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("monitoring appliance is missing Pulse runtime contract %q", expected)
		}
	}
	if strings.Contains(text, "zabbix") || strings.Contains(text, "postgres") {
		t.Fatal("monitoring appliance retains an obsolete product or database contract")
	}
}

func TestPulseRestartsAfterCredentialProjectionOrUnhealthyStart(t *testing.T) {
	basePath := filepath.Join("..", "..", "ansible", "roles", "base", "tasks", "main.yml")
	baseData, err := os.ReadFile(basePath)
	if err != nil {
		t.Fatal(err)
	}
	baseText := string(baseData)
	if !strings.Contains(baseText, "register: boetticher_credential_dropin_install") {
		t.Fatal("credential drop-in installation does not expose its change state")
	}

	monitorPath := filepath.Join("..", "..", "ansible", "roles", "monitor", "tasks", "main.yml")
	monitorData, err := os.ReadFile(monitorPath)
	if err != nil {
		t.Fatal(err)
	}
	monitorText := string(monitorData)
	for _, required := range []string{
		"systemctl show pulse --property=ActiveState --property=SubState --value",
		"test -s /run/credentials/pulse.service/pulse-admin-password",
		"boetticher_credential_dropin_install is changed",
		"pulse_service_state.stdout_lines | default([]) != ['active', 'running']",
		"pulse_runtime_credential.rc | default(1) != 0",
		"state: restarted",
		"daemon_reload: true",
	} {
		if !strings.Contains(monitorText, required) {
			t.Fatalf("Pulse recovery contract is missing %q", required)
		}
	}
}

func TestBifrostRestartsWhenAnyRuntimeCredentialIsMissing(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "bifrost", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, required := range []string{
		"test -s /run/credentials/bifrost.service/{{ upstream.api_key_secret | lower | replace('_', '-') | replace('.', '-') }}",
		"register: bifrost_runtime_credentials",
		"bifrost_runtime_credentials.results | default([]) | selectattr('rc', 'ne', 0) | list | length > 0",
		"register: bifrost_service_start",
		"systemctl show bifrost",
		"ExecMainStatus,StatusText,ExecMainStartTimestamp",
		"register: bifrost_service_diagnostics",
		"register: bifrost_final_service_state",
		"bifrost_final_service_state.stdout_lines | default([]) == ['active', 'running']",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("Bifrost credential recovery contract is missing %q", required)
		}
	}
}

func TestBifrostRoleUsesSmallstepServerCertificateAndRetainsClientMTLS(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "bifrost", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, required := range []string{
		"step_ca_root_cert_pem is defined",
		"step_ca_intermediate_cert_pem is defined",
		"include_tasks: ../../tasks/step-ca-endpoint.yml",
		"step_ca_endpoint_subject: \"bifrost.{{ domain }}\"",
		"ssl_verify_client on;",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("Bifrost TLS contract is missing %q", required)
		}
	}
	for _, forbidden := range []string{"bifrost_server_cert_pem", "bifrost.csr.pem", "ansible.builtin.fetch:"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("Bifrost role retains controller server-certificate exchange %q", forbidden)
		}
	}
}

func TestAIOpsRoleUsesSmallstepEndpointIdentities(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "aiops", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, required := range []string{
		"step_ca_root_cert_pem is defined",
		"step_ca_intermediate_cert_pem is defined",
		"include_tasks: ../../tasks/step-ca-endpoint.yml",
		"step_ca_endpoint_subject: \"aiops.{{ domain }}\"",
		"ai-router-client.crt.pem",
		"step_ca_endpoint_subject: aiops-log-read",
		"log-query-client.crt.pem",
		"log-query-client.step-ca",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("AIOps TLS contract is missing %q", required)
		}
	}
	for _, forbidden := range []string{"aiops_server_cert_pem", "aiops_log_read_cert_pem", "log-query-client.csr.pem", "pki_csr_output_dir"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("AIOps role retains controller server-certificate exchange %q", forbidden)
		}
	}
}

func TestMonitoringFrontendHandlersFlushBeforeReconciliation(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "monitor", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "Reload nginx after enabling the monitoring frontend") || !strings.Contains(text, "state: reloaded") {
		t.Fatal("monitoring frontend is not reloaded before controller reconciliation")
	}
}

func TestEndpointTLSKeysRemainLocallyOwnedAndNeverSuppliedByController(t *testing.T) {
	for _, role := range []string{"monitor"} {
		path := filepath.Join("..", "..", "ansible", "roles", role, "tasks", "main.yml")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		if !strings.Contains(text, "endpoint-owned key") || !strings.Contains(text, role+".key.pem.new") {
			t.Fatalf("%s role does not generate and activate its endpoint-owned key locally", role)
		}
		if strings.Contains(text, role+"_server_key_pem") {
			t.Fatalf("%s role still accepts a controller-supplied endpoint private key", role)
		}
		if strings.Contains(text, "ansible.builtin.fetch:") || strings.Contains(text, role+".csr.pem") {
			t.Fatalf("%s role retains a controller-side CSR exchange", role)
		}
	}
}

func TestGuestPlaybookProjectsLoggingClientsBeyondTheCollector(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "ansible", "site.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "inventory_hostname in logging_upload_configs or inventory_hostname == 'lab-log-01'") {
		t.Fatal("managed guest playbook does not apply the logging client role to endpoint sources")
	}
}

func TestLoggingCollectorKeyIsReadableByItsServiceUser(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "logging", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "path: \"{{ logging_plan.remote_journal_path }}\"\n    state: directory\n    owner: root\n    group: systemd-journal-remote\n    mode: '2770'") || !strings.Contains(text, "Grant the managed administrator read access to collected journals") || !strings.Contains(text, "groups: systemd-journal-remote\n    append: true") || !strings.Contains(text, "path: /var/lib/boetticher/identity/logging/collector.key") || !strings.Contains(text, "step_ca_endpoint_key_group: systemd-journal-remote") || !strings.Contains(text, "step_ca_endpoint_key_mode: '0640'") {
		t.Fatal("logging collector private key is not readable by the systemd-journal-remote service user")
	}
}

func TestLoggingCollectorEnforcesClientRevocationAtTLSProxy(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "logging", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, expected := range []string{
		"client-ca.crl.pem",
		"ssl_crl /var/lib/boetticher/identity/logging/client-ca.crl.pem;",
		"ssl_verify_client on;",
		"proxy_pass http://127.0.0.1:{{ logging_plan.collector_backend_port }};",
		"notify: reload nginx",
		"notify: restart journal query",
		"Disable the socket-activated collector listener",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("logging collector TLS revocation boundary is missing %q", expected)
		}
	}
	if strings.Contains(text, "Enable the socket-activated collector listener") || strings.Contains(text, "--listen-https=-3") {
		t.Fatal("logging collector still exposes the direct socket-activated TLS listener")
	}
}

func TestLoggingRoleStopsOptionalAIOpsJournalQueryWhenDisabled(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "logging", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, expected := range []string{
		"Keep the optional AIOps journal query stopped when AIOps is disabled",
		"Clear stale failure state for the disabled AIOps journal query",
		"name: boetticher-log-query",
		"enabled: false",
		"state: stopped",
		"argv: [systemctl, reset-failed, boetticher-log-query]",
		"failed_when: boetticher_log_query_reset.rc != 0 and 'Unit boetticher-log-query.service not loaded.' not in boetticher_log_query_reset.stderr",
		"not (module_configs.aiops is defined and module_configs.aiops.enabled | default(false) | bool)",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("logging role does not disable the optional journal query when AIOps is disabled: missing %q", expected)
		}
	}
}

func TestLoggingUploadKeyIsReadableByItsServiceGroup(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "base", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "Create endpoint-local logging identity directory") || !strings.Contains(text, "group: systemd-journal\n    mode: '0750'") || !strings.Contains(text, "Issue and renew the endpoint-local logging client certificate from Smallstep") || !strings.Contains(text, "step_ca_endpoint_key_group: systemd-journal") || !strings.Contains(text, "step_ca_endpoint_key_mode: '0640'") {
		t.Fatal("journal upload private keys are not readable by the systemd-journal service group")
	}
}

func TestLoggingUploadServiceCanTraverseRuntimeStateParent(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "base", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, name := range []string{
		"Allow endpoint services to traverse the boetticher runtime state path",
		"Allow endpoint services to traverse the boetticher identity path",
	} {
		block := ansibleTaskBlock(text, name)
		if block == "" || !strings.Contains(block, "inventory_hostname in logging_upload_configs") {
			t.Fatalf("journal upload parent traversal task %q is missing its host guard", name)
		}
	}
	for _, expected := range []string{
		"path: /var/lib/boetticher",
		"group: systemd-journal",
		"mode: '0751'",
		"path: /var/lib/boetticher/identity",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("journal upload parent traversal is missing %q", expected)
		}
	}
}

func TestJournalUploadRetriesAfterDependencyStartup(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "base", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "path: /etc/systemd/system/systemd-journal-upload.service.d\n") || !strings.Contains(text, "systemd-journal-upload.service.d/boetticher.conf") || !strings.Contains(text, "RestartSec=15s") || !strings.Contains(text, "Reload systemd after installing journal-upload policy") {
		t.Fatal("journal upload has no bounded retry policy for DNS-dependent startup")
	}
}

func TestProxmoxJournalUploadPinsTheCollectorWithoutChangingHomeDNS(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "base", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, expected := range []string{
		"Pin the Proxmox collector hostname to the managed logging appliance",
		"path: /etc/hosts",
		"{{ logging_plan.collector_address | regex_escape }}",
		"line: \"{{ logging_plan.collector_address }} logs.{{ domain }}\"",
		"inventory_hostname in groups.get('proxmox', [])",
		"inventory_hostname in logging_upload_configs",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("Proxmox journal upload is missing %q", expected)
		}
	}
}

func TestProxmoxBaseConvergenceDoesNotRequireEnterpriseRepositoryRefresh(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "base", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	want := `update_cache: "{{ inventory_hostname not in groups.get('proxmox', []) }}"`
	if strings.Count(text, want) < 2 {
		t.Fatalf("Proxmox base apt tasks do not avoid unauthenticated enterprise refreshes: %s", text)
	}
	cache := `cache_valid_time: "{{ 0 if inventory_hostname in groups.get('proxmox', []) else 3600 }}"`
	if strings.Count(text, cache) < 2 {
		t.Fatalf("Proxmox base apt tasks still force cache refreshes through cache_valid_time: %s", text)
	}
}

func TestPulseAgentPinsTheMonitoringHostnameForTaggedTargets(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "base", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, expected := range []string{
		"Pin the Pulse monitoring hostname for host agents",
		"monitoring_plan.components",
		"map(attribute='address')",
		"monitor.{{ domain }}",
		"inventory_hostname in (pulse_agent_targets | default([]))",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("Pulse host-agent monitoring mapping is missing %q", expected)
		}
	}
}

func TestMonitorPinsTheProxmoxCertificateHostname(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "base", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, expected := range []string{
		"Pin the Proxmox API certificate hostname for Pulse",
		"{{ proxmox_management_address | regex_escape }}",
		"line: \"{{ proxmox_management_address }} proxmox\"",
		"inventory_hostname == 'lab-monitor-01'",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("Pulse Proxmox certificate hostname mapping is missing %q", expected)
		}
	}
}

func TestApplianceResolverUsesPlatformDNSPair(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "base", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "Configure appliances to use the platform DNS pair") || !strings.Contains(text, "nameserver {{ nameserver }}") || !strings.Contains(text, "dest: /etc/resolv.conf") || !strings.Contains(text, "inventory_hostname not in groups.get('proxmox', [])") {
		t.Fatal("appliances do not receive the model DNS pair without modifying the Proxmox host")
	}
}

func TestManagedPlaybookDoesNotUseDurableBecomeEscalation(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "ansible", "site.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "become: false") || strings.Contains(text, "become: true") {
		t.Fatalf("managed playbook retains a durable become path: %s", text)
	}
}

func TestBaseRoleRemovesLegacyLabadminPrivilegeContracts(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "base", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, required := range []string{"gpasswd --delete labadmin sudo", "/etc/sudoers.d/boetticher", "/etc/sudoers.d/boetticher-labadmin", "failed_when: remove_labadmin_sudo_group.rc not in [0, 3]"} {
		if !strings.Contains(text, required) {
			t.Fatalf("base role does not remove legacy privilege contract %q", required)
		}
	}
}

func TestBaseRoleRunsChronyWithoutKernelClockControlInAppliances(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "base", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, expected := range []string{
		"content: \"DAEMON_OPTS=\\\"-x\\\"\\n\"",
		"dest: /etc/default/chrony",
		"path: /etc/systemd/system/chrony.service.d",
		"state: directory",
		"content: \"[Unit]\\nAfter=network-online.target\\nWants=network-online.target\\nConditionCapability=\\n\"",
		"dest: /etc/systemd/system/chrony.service.d/boetticher.conf",
		"notify: reload systemd",
		"name: chronyd-restricted.service",
		"enabled: false",
		"state: stopped",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("base role missing %q", expected)
		}
	}
	chronyBlock := ansibleTaskBlock(text, "Configure Chrony for unprivileged appliances")
	if chronyBlock == "" || !strings.Contains(chronyBlock, "inventory_hostname not in groups.get('proxmox', [])") {
		t.Fatal("base role does not restrict unprivileged Chrony configuration to appliances")
	}
}

func TestDNSRoleChecksPowerDNSVersionOutputOnEitherStream(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "dns", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "'4.9.17' in powerdns_version.stdout or '4.9.17' in powerdns_version.stderr") {
		t.Fatal("DNS role ignores PowerDNS version output written to stderr")
	}
}

func TestDNSRoleInstallsSmallstepWithColdRootBoundary(t *testing.T) {
	tasksPath := filepath.Join("..", "..", "ansible", "roles", "dns", "tasks", "main.yml")
	tasks, err := os.ReadFile(tasksPath)
	if err != nil {
		t.Fatal(err)
	}
	servicePath := filepath.Join("..", "..", "ansible", "roles", "dns", "templates", "step-ca.service.j2")
	service, err := os.ReadFile(servicePath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(tasks) + string(service)
	for _, expected := range []string{
		"name: boetticher-step-ca",
		"/usr/local/bin/step",
		"--password-file",
		"--acme",
		"step_ca_root_cert_pem",
		"step_ca_intermediate_cert_pem",
		"step_ca_intermediate_key_pem",
		"Remove the generated Smallstep root private key from the online CA",
		"User=boetticher-step-ca",
		"NoNewPrivileges=true",
		"ProtectSystem=strict",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("Smallstep CA runtime contract is missing %q", expected)
		}
	}
	if strings.Contains(text, "step_ca_root_key_pem") || strings.Contains(text, "root_key_pem_b64") {
		t.Fatal("DNS role attempts to deliver the cold root private key")
	}
	if strings.Index(string(tasks), "Remove the generated Smallstep root private key from the online CA") < strings.Index(string(tasks), "Initialize the Smallstep CA configuration once") {
		t.Fatal("DNS role removes the generated root key before initializing Smallstep")
	}
}

func TestDNSRoleUsesPowerDNS49CommandNames(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "dns", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, forbidden := range []string{"pdnsutil zone ", "pdnsutil rrset ", "pdnsutil metadata "} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("DNS role retains obsolete PowerDNS command namespace %q", forbidden)
		}
	}
	for _, expected := range []string{"pdnsutil list-all-zones", "pdnsutil create-zone", "pdnsutil set-kind {{ item }} MASTER", "pdnsutil replace-rrset", "pdnsutil delete-rrset", "pdnsutil set-meta", "NOTIFY-DNSUPDATE 1", "pdnsutil replace-rrset \"$zone\" @ NS", "item.name | replace('.' ~ dns_plan.static_zone, '')", "item.value"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("DNS role missing qualified PowerDNS command %q", expected)
		}
	}
	if strings.Contains(text, "item.address") {
		t.Fatal("DNS role uses an unavailable address field for static records")
	}
}

func TestFirewallDHCPTemplateProjectsExplicitReservations(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "firewall", "templates", "kea-dhcp4.conf.j2")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, expected := range []string{"\"dhcp-ddns\": {", "\"enable-updates\": true", "\"server-ip\": \"127.0.0.1\"", "\"server-port\": 53001", "subnet.get('reservations'", "hw-address", "ip-address", "hostname"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("Kea template does not project reservation field %q", expected)
		}
	}
}

func TestDNSRoleUsesBlockyVersionSubcommand(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "dns", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "ansible.builtin.command: blocky version") {
		t.Fatal("DNS role does not use Blocky's supported version subcommand")
	}
	if strings.Contains(text, "blocky --version") {
		t.Fatal("DNS role retains Blocky's unsupported --version flag")
	}
}

func TestDNSRoleAllowsBlockyToTraverseFilteringPolicy(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "dns", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, required := range []string{"Allow Blocky to traverse its non-secret filtering policy path", "path: /etc/boetticher", "mode: '0755'"} {
		if !strings.Contains(text, required) {
			t.Fatalf("DNS role is missing Blocky filtering traversal contract %q", required)
		}
	}
}

func TestPowerDNSTemplateUsesCurrentPrimarySetting(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "dns", "templates", "pdns.conf.j2")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, forbidden := range []string{"master=", "slave="} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("PowerDNS template retains obsolete setting %q", forbidden)
		}
	}
	for _, expected := range []string{"primary=yes"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("PowerDNS template missing current setting %q", expected)
		}
	}
}

func TestDNSRoleMakesPowerDNSConfigReadableByServiceUser(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "dns", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "dest: /etc/powerdns/pdns.conf\n    owner: root\n    group: pdns\n    mode: '0640'") {
		t.Fatal("PowerDNS configuration is not readable by the pdns service user")
	}
}

func TestMonitoringRoleHasNoDatabaseOrGuestAgentSetup(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "monitor", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, obsolete := range []string{"become_user: postgres", "become_user: zabbix", "runuser -u postgres", "runuser -u zabbix", "zabbix", "postgres"} {
		if strings.Contains(text, obsolete) {
			t.Fatalf("monitoring role retains obsolete setup %q", obsolete)
		}
	}
}

func TestMonitoringRoleUsesExistingTLSBoundary(t *testing.T) {
	tasksPath := filepath.Join("..", "..", "ansible", "roles", "monitor", "tasks", "main.yml")
	tasks, err := os.ReadFile(tasksPath)
	if err != nil {
		t.Fatal(err)
	}
	templatePath := filepath.Join("..", "..", "ansible", "roles", "monitor", "templates", "pulse-loopback.conf.j2")
	template, err := os.ReadFile(templatePath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(tasks) + string(template)
	if !strings.Contains(string(tasks), "content: \"{{ client_crl_bundle_pem }}\"") {
		t.Fatal("Pulse nginx mTLS trust does not use the complete client CRL bundle")
	}
	for _, expected := range []string{"step_ca_root_cert_pem", "step_ca_intermediate_cert_pem", "client_ca_pem", "client_crl_pem", "ssl_crl /etc/boetticher/tls/client-ca.crl.pem", "ssl_verify_client optional", "ssl_verify_depth 3;", "if ($ssl_client_verify != SUCCESS) { return 403; }", "proxy_pass http://127.0.0.1:7655"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("monitoring role missing TLS/frontend contract %q", expected)
		}
	}
}

func TestMonitoringRoleUsesEndpointOwnedSmallstepRenewal(t *testing.T) {
	tasks, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "monitor", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"step-ca-root.crt",
		"step-ca-intermediate.crt",
		"Create a one-time Pulse certificate token on the online CA",
		"monitor_step_ca_token_raw",
		"stdout_lines | last",
		"monitor_step_ca_token_value is match",
		"Issue the Pulse certificate from Smallstep with an endpoint-owned key",
		"monitor.crt.pem.new",
		"monitor.key.pem.new",
		"monitor.step-ca",
		"boetticher-renew-monitor-certificate.timer",
	} {
		if !strings.Contains(string(tasks), name) {
			t.Fatalf("monitoring role is missing Smallstep renewal contract %q", name)
		}
	}
	script, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "monitor", "templates", "renew-monitor-certificate.sh.j2"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"certificate needs-renewal",
		"ca renew --force --expires-in 240h",
		"certificate bundle",
		"certificate verify",
		"mv -f \"$work/bundle.pem\" \"$cert\"",
		"systemctl reload nginx",
	} {
		if !strings.Contains(string(script), name) {
			t.Fatalf("monitor renewal helper is missing %q", name)
		}
	}
	service, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "monitor", "templates", "renew-monitor-certificate.service.j2"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(service), "User=root") || !strings.Contains(string(service), "ProtectSystem=strict") {
		t.Fatal("monitor renewal service does not retain the narrow root-owned key boundary")
	}
}

func TestMonitoringRoleCreatesPulseStateDirectory(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "monitor", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "path: /var/lib/pulse\n    state: directory\n    owner: pulse\n    group: pulse\n    mode: '0700'") {
		t.Fatal("monitoring role does not create the Pulse state directory")
	}
}

func TestFirewallRoleCreatesNftablesConfigurationDirectory(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "firewall", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, expected := range []string{"- name: Create nftables configuration directory", "path: /etc/nftables.d", "state: directory"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("firewall role missing %q", expected)
		}
	}
}

func TestFirewallPolicyRoutingCleanupIsIdempotentWhenTableIsAbsent(t *testing.T) {
	tasksPath := filepath.Join("..", "..", "ansible", "roles", "firewall", "tasks", "main.yml")
	tasksData, err := os.ReadFile(tasksPath)
	if err != nil {
		t.Fatal(err)
	}
	templatePath := filepath.Join("..", "..", "ansible", "roles", "firewall", "templates", "boetticher-policy-routing-down.j2")
	templateData, err := os.ReadFile(templatePath)
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"firewall cleanup task": string(tasksData)} {
		if !strings.Contains(text, "route_status=0") || !strings.Contains(text, "FIB table does not exist") || !strings.Contains(text, "exit \"$route_status\"") {
			t.Fatalf("%s does not preserve idempotent route-table cleanup", name)
		}
	}
	if !strings.Contains(string(templateData), "unreachable default") || strings.Contains(string(templateData), "rule del") || strings.Contains(string(templateData), "route flush") {
		t.Fatal("stopping AirVPN policy routing must retain fail-closed fallback")
	}
}

func TestFirewallTelemetryHasFixedReadOnlyPrivilegeAndNetworkContract(t *testing.T) {
	unitPath := filepath.Join("..", "..", "images", "firewall", "runtime", "boetticher-firewall-telemetry.service")
	unitData, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	unit := string(unitData)
	for _, expected := range []string{
		"ExecStart=/usr/lib/boetticher/boetticher-firewall-telemetry",
		"User=boetticher-telemetry",
		"Group=boetticher-telemetry",
		"RuntimeDirectoryMode=0770",
		"NoNewPrivileges=yes",
		"CapabilityBoundingSet=",
		"ProtectSystem=strict",
		"ReadWritePaths=/var/lib/boetticher/firewall-telemetry",
		"IPAddressDeny=any",
		"IPAddressAllow=10.10.10.20/32",
	} {
		if !strings.Contains(unit, expected) {
			t.Fatalf("firewall telemetry unit missing %q", expected)
		}
	}
	snapshotUnitPath := filepath.Join("..", "..", "images", "firewall", "runtime", "boetticher-firewall-snapshot.service")
	snapshotUnitData, err := os.ReadFile(snapshotUnitPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(snapshotUnitData), "User=root\nGroup=boetticher-telemetry\n") {
		t.Fatal("firewall telemetry snapshot unit cannot write its group-owned runtime directory")
	}
	snapshotPath := filepath.Join("..", "..", "images", "firewall", "runtime", "snapshot-firewall.sh")
	snapshotData, err := os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := string(snapshotData)
	if !strings.Contains(snapshot, "/usr/sbin/nft --json list ruleset") || strings.Contains(snapshot, "nft -f") || strings.Contains(snapshot, "nft add") || strings.Contains(snapshot, "nft delete") {
		t.Fatalf("snapshot helper does not preserve the fixed read-only nft boundary: %s", snapshot)
	}
	tasksPath := filepath.Join("..", "..", "ansible", "roles", "firewall", "tasks", "main.yml")
	tasksData, err := os.ReadFile(tasksPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"boetticher-firewall-snapshot.timer", "boetticher-firewall-telemetry.service", "path: /var/lib/boetticher/firewall-telemetry", "owner: boetticher-telemetry"} {
		if !strings.Contains(string(tasksData), expected) {
			t.Fatalf("firewall role missing telemetry contract %q", expected)
		}
	}
	buildData, err := os.ReadFile(filepath.Join("..", "..", "scripts", "build-images.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"go build -trimpath -o \"$telemetry_binary\" ./cmd/boetticher-firewall-telemetry",
		"--upload \"$telemetry_binary:/usr/lib/boetticher/boetticher-firewall-telemetry\"",
		"groupadd --system boetticher-telemetry",
		"systemctl enable boetticher-firewall-telemetry.service boetticher-firewall-snapshot.timer",
	} {
		if !strings.Contains(string(buildData), expected) {
			t.Fatalf("firewall image build is missing telemetry contract %q", expected)
		}
	}
}

func TestFirewallRolePersistsForwardingReadinessGate(t *testing.T) {
	tasksPath := filepath.Join("..", "..", "ansible", "roles", "firewall", "tasks", "main.yml")
	tasksData, err := os.ReadFile(tasksPath)
	if err != nil {
		t.Fatal(err)
	}
	tasks := string(tasksData)
	for _, expected := range []string{
		"src: boetticher-forwarding.service.j2",
		"dest: /etc/systemd/system/boetticher-forwarding.service",
		"name: boetticher-forwarding.service",
		"enabled: true",
		"daemon_reload: true",
		"name: Reassert IPv4 forwarding after the readiness gate",
		"argv: [sysctl, -w, net.ipv4.ip_forward=1]",
		"changed_when: false",
	} {
		if !strings.Contains(tasks, expected) {
			t.Fatalf("firewall role missing forwarding readiness gate contract %q", expected)
		}
	}

	unitPath := filepath.Join("..", "..", "ansible", "roles", "firewall", "templates", "boetticher-forwarding.service.j2")
	unitData, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	unit := string(unitData)
	for _, expected := range []string{
		"Requires=nftables.service kea-dhcp4-server.service kea-dhcp-ddns-server.service dnsmasq.service",
		"After=network-online.target nftables.service kea-dhcp4-server.service kea-dhcp-ddns-server.service dnsmasq.service",
		"ExecStart=/usr/sbin/sysctl -w net.ipv4.ip_forward=1",
		"ExecStop=/usr/sbin/sysctl -w net.ipv4.ip_forward=0",
	} {
		if !strings.Contains(unit, expected) {
			t.Fatalf("forwarding readiness gate missing %q", expected)
		}
	}
}

func TestFirewallRoleAllowsKeaCredentialThroughAppArmor(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "firewall", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, expected := range []string{
		"Allow Kea DDNS to read its systemd credential",
		"/run/credentials/kea-dhcp-ddns-server.service/kea-ddns-tsig r,",
		"dest: /etc/apparmor.d/local/usr.sbin.kea-dhcp-ddns",
		"notify: reload AppArmor",
		"Permit read-only Kea lease evidence",
		"labadmin ALL=(root) NOPASSWD: /bin/cat /var/lib/kea/kea-leases4.csv",
		"dest: /etc/sudoers.d/boetticher-kea-leases",
		"validate: /usr/sbin/visudo -cf %s",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("firewall role missing Kea AppArmor rule %q", expected)
		}
	}
}

func TestKeaTemplateHandlesOptionalDHCPPool(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "firewall", "templates", "kea-dhcp4.conf.j2")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "subnet.get('pool', '')") {
		t.Fatal("Kea template does not default the optional DHCP pool")
	}
}

func TestVariablesContainDNSConvergenceContractWithoutSecrets(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	variables, err := Variables(site)
	if err != nil {
		t.Fatal(err)
	}
	text := string(variables)
	for _, expected := range []string{
		`"authoritative_dns": "PowerDNS Authoritative"`,
		`"authoritative_dns_version": "4.9.17"`,
		`"authoritative_package_version": "4.9.17-1pdns.trixie"`,
		`"authoritative_dns_port": "5353"`,
		`"trusted.lab.home.arpa"`,
		`"sandbox.lab.home.arpa"`,
		`"blocky_config"`,
		`"firewall_interface_config_digests"`,
		`upstreams:\n    groups:\n        default:`,
		`"usb_export_manifests": []`,
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("Ansible variables missing %q", expected)
		}
	}
	if strings.Contains(text, "c2VjcmV0") {
		t.Fatal("generated Ansible variables contain secret material")
	}
}

func TestDNSAuthoritativeUpdatesAreGatedByLiveRRsetState(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "dns", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, expected := range []string{
		"Check whether the PowerDNS database exists",
		"not powerdns_database.stat.exists",
		"Initialize authoritative NS records on the primary when changed",
		"Publish model-owned static DNS records to the primary when changed",
		"pdnsutil list-zone",
		"Remove exact malformed PowerDNS static rrsets from the prior boetticher attempt",
		"updated=0",
		"changed_when: \"'updated' in malformed_static_rrsets.stdout\"",
		"changed_when: \"'updated' in malformed_ns_rrsets.stdout\"",
		"changed_when: \"'updated' in static_dns_records.stdout\"",
		"$4 == \"NS\"",
		"$5 == \"lab-dns-01.{{ dns_plan.static_zone }}.\"",
		"pdnsutil delete-rrset {{ item | quote }} {{ item | quote }} NS",
		"$4 == record_type",
		"normalized($5) == normalized(wanted)",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("DNS role is missing live RRset convergence guard %q", expected)
		}
	}
	if strings.Contains(text, "loop: \"{{ dns_plan.static_records }}\"") {
		t.Fatal("DNS role still runs one malformed static-record probe per record")
	}
}

func TestDNSDDNSMetadataIsReconciledAgainstLivePowerDNSState(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "dns", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, expected := range []string{
		"Reconcile Kea DDNS metadata on the primary when changed",
		"pdnsutil get-meta",
		"metadata_values()",
		"tr ',' ' '",
		"pdnsutil set-meta \"$zone\" ALLOW-DNSUPDATE-FROM {% for source in dns_plan.ddns.update_sources %}{{ source | quote }} {% endfor %};",
		"changed_when: \"'updated' in ddns_metadata.stdout\"",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("DNS role is missing DDNS metadata convergence guard %q", expected)
		}
	}
	if strings.Contains(text, "Authorize Kea DDNS updates for dynamic forward zones") || strings.Contains(text, "Authorize Kea DDNS updates for reverse zones") {
		t.Fatal("DNS role retains unconditional forward or reverse DDNS metadata tasks")
	}
}

func TestDNSAppliancePathCannotInstallAResolver(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "dns", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, forbidden := range []string{"ansible.builtin.get_url:", "ansible.builtin.unarchive:"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("DNS role retains software installation path %q", forbidden)
		}
	}
	if !strings.Contains(text, "Assert the qualified Blocky binary is present") || !strings.Contains(text, "ansible.builtin.command: blocky version") {
		t.Fatal("DNS appliance path does not assert that the selected binary is image-provided")
	}
}

func TestApplianceRolesDoNotMutateModuleSoftware(t *testing.T) {
	for _, role := range []string{"dns", "monitor", "firewall", "logging"} {
		path := filepath.Join("..", "..", "ansible", "roles", role, "tasks", "main.yml")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		for _, forbidden := range []string{"ansible.builtin.apt:", "ansible.builtin.apt_repository:", "ansible.builtin.get_url:"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s appliance role retains software mutation task %q", role, forbidden)
			}
		}
		if strings.Contains(text, "ansible.builtin.unarchive:") {
			t.Fatalf("%s appliance role retains software mutation task %q", role, "ansible.builtin.unarchive:")
		}
		if !strings.Contains(text, "boetticher_appliance_artifact") {
			t.Fatalf("%s appliance role does not require the qualified artifact path", role)
		}
	}
}

func TestFirewallKeaCredentialDropinIsActivatedAfterProjection(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "base", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	start := strings.Index(text, "- name: Activate the firewall Kea DDNS credential drop-in")
	if start < 0 {
		t.Fatal("base role is missing firewall Kea credential activation")
	}
	end := strings.Index(text[start:], "\n- name:")
	if end < 0 {
		end = len(text) - start
	}
	task := text[start : start+end]
	for _, required := range []string{
		"name: kea-dhcp-ddns-server.service",
		"state: restarted",
		"daemon_reload: true",
		"inventory_hostname in groups.get('firewall', [])",
		"boetticher_deploy_phase | default('full') in ['full', 'bootstrap']",
		"credential_dropins[inventory_hostname]['kea-dhcp-ddns-server.service'] is defined",
	} {
		if !strings.Contains(task, required) {
			t.Fatalf("firewall Kea credential activation is missing %q", required)
		}
	}
}

func TestFirewallInterfaceBindingsCarryStableRoleMACs(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	variables, err := Variables(site)
	if err != nil {
		t.Fatal(err)
	}
	text := string(variables)
	for _, expected := range []string{
		`"name": "wan0"`, `"mac": "02:00:00:00:01:01"`,
		`"name": "trusted0"`, `"mac": "02:00:00:00:01:02"`,
		`"name": "servers0"`, `"mac": "02:00:00:00:01:03"`,
		`"name": "sandbox0"`, `"mac": "02:00:00:00:01:04"`,
		`"name": "mgmt0"`, `"mac": "02:00:00:00:01:05"`,
		`"name": "transit0"`, `"mac": "02:00:00:00:01:06"`,
		`"name": "infra0"`, `"mac": "02:00:00:00:01:07"`,
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("firewall variables missing stable interface binding %q", expected)
		}
	}
}

func TestDNSRoleDoesNotPlaceTSIGSecretsInProcessArguments(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "dns", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "ddns_tsig_secret") || strings.Contains(text, "INSERT OR REPLACE INTO tsigkeys") {
		t.Fatal("DNS role still receives or persists TSIG material through Ansible variables")
	}
	kea, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "firewall", "templates", "kea-dhcp-ddns.conf.j2"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(kea), "secret-file") || strings.Contains(string(kea), "{{ ddns_tsig_secret }}") {
		t.Fatal("Kea does not consume its TSIG through the systemd credential runtime file")
	}
	keaText := string(kea)
	if !strings.Contains(keaText, `"forward-ddns": {`) || !strings.Contains(keaText, `"reverse-ddns": {`) || !strings.Contains(keaText, `"ddns-domains":`) || !strings.Contains(keaText, `"key-name": "{{ zone.tsig_key_name }}"`) {
		t.Fatal("Kea D2 does not use the qualified domain catalogs and TSIG key references")
	}
	for _, expected := range []string{
		`"dns-server-timeout": {{ firewall_plan.ddns.dns_response_timeout_ms }},`,
		`"name": "{{ zone.forward_zone }}."`,
		`"name": "{{ zone.reverse_zone }}."`,
	} {
		if !strings.Contains(keaText, expected) {
			t.Errorf("Kea D2 domain catalog does not use a fully qualified zone name: %s", expected)
		}
	}
	if strings.Contains(keaText, `"dns-server-timeout": 500,`) {
		t.Fatal("Kea D2 still uses the default response timeout instead of the generated DDNS contract")
	}
}

func TestPowerDNSBindsEachDNSGuestAddressAlongsideLoopback(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "dns", "templates", "pdns.conf.j2")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "local-address=127.0.0.1,{{ ansible_host }}") {
		t.Fatal("PowerDNS does not bind loopback and the current DNS guest address")
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "local-address=") && strings.Contains(line, "10.10.10.10") {
			t.Fatal("PowerDNS local listener hard-codes the primary address for both DNS guests")
		}
	}
}

func TestFirstPartyRolesKeepRuntimeAndTrustBoundaries(t *testing.T) {
	tests := []struct {
		role      string
		required  []string
		forbidden []string
	}{
		{
			role: "tailnet-router",
			required: []string{
				"boetticher_appliance_artifact",
				"ExecStartPost=/usr/lib/boetticher/tailscale-router-bootstrap",
				"/var/lib/tailscale",
				"/etc/sysctl.d/99-boetticher-tailnet-router.conf",
				"net.ipv4.ip_forward=1",
				"argv: [sysctl, -w, net.ipv4.ip_forward=1]",
				"After=network-online.target",
				"Wants=network-online.target",
				"tailscale status --json",
				"BackendState",
				"Running",
				"Inspect Tailscale backend state after credential projection",
				"state: restarted",
				"daemon_reload: true",
				"retries: 15",
				"delay: 2",
				"until:",
				`regex_search('"BackendState"\s*:\s*"Running"')`,
				"if [ -s \"$credential\" ] && tailscale up --timeout=30s --auth-key=\"file:$credential\"",
				"tailscale up --timeout=30s",
				"--accept-dns=false",
				"--advertise-routes=10.10.0.0/16",
				"--snat-subnet-routes=true",
				"enable_forwarding()",
				"enable_forwarding\n",
			},
			forbidden: []string{"--advertise-exit-node=true", "privileged: true", "ansible.builtin.apt:", `regex_search('"BackendState"[[:space:]]*`},
		},
		{
			role: "logging",
			required: []string{
				"logging_collector_socket_override",
				"systemd-journal-remote.socket.d",
				"content: \"{{ logging_collector_socket_override }}\"",
				"Reload logging systemd units after collector override installation",
				"Reload nginx after enabling the journal mTLS proxy",
				"state: reloaded",
			},
			forbidden: []string{"ListenStream=19532"},
		},
		{
			role: "bifrost",
			required: []string{
				"boetticher_appliance_artifact",
				"no_log: true",
				"dest: /etc/boetticher/bifrost/config.json",
				"group: bifrost",
				"path: /etc/boetticher/bifrost",
				"mode: '0751'",
				"ssl_verify_client on;",
				"proxy_pass http://127.0.0.1:4000;",
				"listen 10.10.20.60:443 ssl;",
				"location ^~ /internal/ {",
				"return 404;",
				"proxy_pass http://127.0.0.1:4000;",
				"path: /etc/systemd/system/nginx.service.d",
				"dest: /etc/systemd/system/nginx.service.d/boetticher-network.conf",
				"After=network-online.target",
				"Wants=network-online.target",
				"notify: restart nginx",
				"Restart Bifrost after credential projection or an unhealthy start",
				"systemctl show bifrost --property=ActiveState --property=SubState --value",
				"daemon_reload: true",
				"/run/credentials/bifrost.service/{{ upstream.api_key_secret | lower | replace('_', '-') | replace('.', '-') }}",
			},
			forbidden: []string{"listen 10.10.20.60:80", "api_key: {{", "ansible.builtin.get_url:"},
		},
		{
			role: "printer",
			required: []string{
				"boetticher_appliance_artifact",
				"client_ca_pem | default('') | length > 0",
				"ssl_client_certificate /var/lib/boetticher/identity/tls/client-ca.pem;",
				"ssl_verify_client on;",
				"proxy_pass http://127.0.0.1:5000;",
				"listen 10.10.20.80:443 ssl;",
				"Wait for the OctoPrint backend before advertising the endpoint",
				"url: http://127.0.0.1:5000/",
				"until: octoprint_backend.status | default(0) == 200",
				"Verify a client without a certificate is rejected before OctoPrint",
				"ca_path: /var/lib/boetticher/identity/tls/client-ca.pem",
				"status_code: 400",
			},
			forbidden: []string{"ssl_verify_client off", "listen 10.10.20.80:80", "ansible.builtin.apt:"},
		},
	}
	for _, test := range tests {
		path := filepath.Join("..", "..", "ansible", "roles", test.role, "tasks", "main.yml")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		for _, required := range test.required {
			if !strings.Contains(text, required) {
				t.Errorf("%s role is missing bounded runtime contract %q", test.role, required)
			}
		}
		for _, forbidden := range test.forbidden {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s role contains forbidden runtime contract %q", test.role, forbidden)
			}
		}
	}
}
func TestPulseProxyAuthMapsOnlyApprovedClientIdentities(t *testing.T) {
	frontend, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "monitor", "templates", "pulse-loopback.conf.j2"))
	if err != nil {
		t.Fatal(err)
	}
	tasks, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "monitor", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "monitor", "templates", "pulse-nginx-proxy-auth.sh.j2"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(frontend)
	contract := text + string(tasks) + string(renderer)
	for _, expected := range []string{
		"CN=client-operator.{{ domain }},O=boetticher",
		"CN=client-lab-display-01-kiosk.{{ domain }},O=boetticher",
		"location = /api/health",
		"location = /api/state/summary",
		"location = /api/resources",
		"proxy_set_header X-API-Token $http_x_api_token",
		"include /run/boetticher/pulse-proxy-auth.conf",
		"set $boetticher_pulse_proxy_shared_secret",
		"set $boetticher_pulse_proxy_secret $boetticher_pulse_proxy_shared_secret",
		"proxy_set_header X-Proxy-Secret $boetticher_pulse_proxy_secret",
		"ExecStartPre=/usr/local/sbin/boetticher-pulse-nginx-proxy-auth",
		"ExecStartPre=\n      ExecStartPre=/usr/local/sbin/boetticher-pulse-nginx-proxy-auth",
		"ExecStartPre=/usr/sbin/nginx -t -q -g 'daemon on; master_process on;'",
		"daemon_reload: true",
	} {
		if !strings.Contains(contract, expected) {
			t.Fatalf("Pulse proxy-auth contract is missing %q", expected)
		}
	}
	if rendererIndex, nginxCheckIndex := strings.Index(string(tasks), "ExecStartPre=/usr/local/sbin/boetticher-pulse-nginx-proxy-auth"), strings.Index(string(tasks), "ExecStartPre=/usr/sbin/nginx -t -q -g 'daemon on; master_process on;'"); rendererIndex == -1 || nginxCheckIndex == -1 || rendererIndex >= nginxCheckIndex {
		t.Fatal("Pulse proxy-auth renderer must run before nginx's built-in configuration check")
	}
	if got := strings.Count(text, "proxy_set_header X-Proxy-Secret \"\";"); got != 4 {
		t.Fatalf("frontend clears incoming proxy secret in %d locations, want the host-agent and three StreamDeck API locations", got)
	}
	if got := strings.Count(text, "proxy_set_header X-Proxy-Secret $boetticher_pulse_proxy_secret;"); got != 5 {
		t.Fatalf("frontend maps proxy secret in %d browser locations, want 5", got)
	}
	if got := strings.Count(text, "set $boetticher_pulse_proxy_secret \"\";"); got != 4 {
		t.Fatalf("frontend initializes conditional proxy secret in %d API locations, want 4", got)
	}
	if strings.Contains(text, "$ssl_client_cert") || strings.Contains(text, "$ssl_client_s_dn;\n") {
		t.Fatal("frontend forwards an arbitrary client certificate identity")
	}
	if !strings.HasSuffix(strings.TrimSpace(text), "}") {
		t.Fatal("Pulse frontend template has directives outside its server block")
	}
	agentStart := strings.Index(text, "location ^~ /api/agents/")
	if agentStart < 0 {
		t.Fatal("Pulse frontend is missing the host-agent location")
	}
	agentEnd := strings.Index(text[agentStart:], "\n    }")
	if agentEnd < 0 {
		t.Fatal("Pulse host-agent location is malformed")
	}
	if !strings.Contains(text[agentStart:agentStart+agentEnd], "proxy_set_header X-Proxy-Secret \"\";") {
		t.Fatal("Pulse host-agent location does not clear browser proxy auth")
	}
}

func TestSharedClientCAFrontendsRestrictClientIdentities(t *testing.T) {
	checks := []struct {
		role     string
		required []string
	}{
		{role: "bifrost", required: []string{
			`if ($ssl_client_s_dn !~ "^(?:CN=client-operator\\.{{ domain | regex_escape }}(?:,O=boetticher)?|CN=client-aiops-router-client\\.{{ domain | regex_escape }}(?:,O=boetticher)?)$") { return 403; }`,
			`if ($ssl_client_s_dn ~ "CN=client-aiops-router-client(?:\\.|,|$)") { return 403; }`,
		}},
		{role: "arr", required: []string{`if ($ssl_client_s_dn != "CN=client-operator.{{ domain }},O=boetticher") { return 403; }`}},
		{role: "printer", required: []string{`if ($ssl_client_s_dn != "CN=client-operator.{{ domain }},O=boetticher") { return 403; }`}},
	}
	for _, check := range checks {
		data, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", check.role, "tasks", "main.yml"))
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		for _, required := range check.required {
			if !strings.Contains(text, required) {
				t.Fatalf("%s frontend is missing exact client identity control %q", check.role, required)
			}
		}
	}
}

func TestLoggingUploadRetainsClientIdentityAndPulseWritesUseScopedTokens(t *testing.T) {
	logging, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "logging", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	loggingText := string(logging)
	for _, required := range []string{
		"set $boetticher_logging_client_allowed 0;",
		"logging_upload_configs.keys() | sort",
		`CN=client-{{ endpoint | regex_escape }}\\.{{ domain | regex_escape }}(?:,O=boetticher)?`,
		"if ($boetticher_logging_client_allowed = 0) { return 403; }",
	} {
		if !strings.Contains(loggingText, required) {
			t.Fatalf("logging upload route is missing exact client identity control %q", required)
		}
	}
	frontend, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "monitor", "templates", "pulse-loopback.conf.j2"))
	if err != nil {
		t.Fatal(err)
	}
	frontendText := string(frontend)
	noteStart := strings.Index(frontendText, "location = /api/alerts/incidents/note")
	if noteStart < 0 {
		t.Fatal("Pulse incident-note route is missing")
	}
	noteEnd := strings.Index(frontendText[noteStart:], "\n    }")
	if noteEnd < 0 {
		t.Fatal("Pulse incident-note route is unterminated")
	}
	noteRoute := frontendText[noteStart : noteStart+noteEnd]
	if strings.Contains(noteRoute, "$ssl_client_verify") || strings.Contains(noteRoute, "$ssl_client_s_dn") || !strings.Contains(noteRoute, "Authorization $http_authorization") {
		t.Fatal("Pulse incident-note route does not use the scoped bearer-token boundary")
	}
}

func TestPiKioskUsesLocalCredentialFreeDashboard(t *testing.T) {
	TestCompanionKioskIsCredentialFreeAndKeyboardFree(t)
	TestCompanionCleanupFollowsFunctionalCheck(t)
}

func TestKioskRoleRequiresPrestreamedEncryptedCredentials(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "kiosk", "tasks", "credential.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, required := range []string{
		"separately streamed encrypted credential",
		"installed_credential.stat.exists",
		"installed_credential.stat.isreg",
		"installed_credential.stat.pw_name == 'root'",
		"installed_credential.stat.gr_name == 'root'",
		"installed_credential.stat.mode == '0600'",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("kiosk role is missing idempotent update guard %q", required)
		}
	}
	for _, forbidden := range []string{"credential_value", "systemd-creds", "ansible.builtin.tempfile", "ansible.builtin.copy"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("kiosk credential verification accepts plaintext transport %q", forbidden)
		}
	}
	// Certificates are retired rather than reimported: the new kiosk has no
	// remote credentials. Retain the migration check for old NSS material.
	TestCompanionCleanupFollowsFunctionalCheck(t)
}

func TestAnsibleOutputChangedUsesRecapOnly(t *testing.T) {
	for _, test := range []struct {
		name    string
		output  string
		changed bool
	}{
		{name: "unchanged", output: "ok=4 changed=0 unreachable=0 failed=0", changed: false},
		{name: "changed", output: "ok=4 changed=1 unreachable=0 failed=0", changed: true},
		{name: "failure without recap", output: "fatal: guest failed", changed: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ansibleOutputChanged([]byte(test.output)); got != test.changed {
				t.Fatalf("ansibleOutputChanged(%q) = %t, want %t", test.output, got, test.changed)
			}
		})
	}
}
