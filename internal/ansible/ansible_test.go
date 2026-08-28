package ansible

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

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
		"ansible_remote_tmp=/tmp/boetticher-ansible",
		"[managed:children]",
		"[logging]",
		"lab-log-01 ansible_host=10.10.10.40",
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
		if component.Name == "lab-monitor-01" || component.Name == "lab-dns-01" || component.Name == "lab-portal-01" {
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
		`"pulse_agent_version": "6.1.2"`,
		`"pulse_agent_release_url": "https://github.com/rcourtman/Pulse/releases/download/v6.1.2/pulse-agent-linux-amd64"`,
		`"pulse_agent_release_sha256": "1f3cfda2b112e82f311f05673f750bc6e5cb05bd0f942f9b84d7612d56f1ba75"`,
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

func TestMonitorFrontendKeepsMTLSExceptForScopedAgentRoutes(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "monitor", "templates", "pulse-loopback.conf.j2"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "ssl_verify_client optional") || !strings.Contains(text, "if ($ssl_client_verify != SUCCESS) { return 403; }") {
		t.Fatal("monitor frontend does not distinguish mTLS UI and token-authenticated agent routes")
	}
	if strings.Contains(text, "ssl_verify_client off") {
		t.Fatal("monitor frontend uses an invalid location-scoped client verification directive")
	}
	if !strings.Contains(text, "location ^~ /api/agents/") {
		t.Fatal("monitor frontend does not proxy the supported Pulse agent routes")
	}
}

func TestGeneratedSSHConfigPathIsBoundToInventoryProjection(t *testing.T) {
	got := generatedSSHConfigPath("/tmp/site/generated/ansible/inventory.ini")
	if got != "/tmp/site/generated/ssh/boetticher.conf" {
		t.Fatalf("generated SSH config path = %q", got)
	}
}

func TestRunUsesAnsibleStdinPathForExtraVars(t *testing.T) {
	tempDir := t.TempDir()
	argsPath := filepath.Join(tempDir, "args")
	scriptPath := filepath.Join(tempDir, "ansible-playbook")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$ANSIBLE_ARGS_FILE\"\ncat >/dev/null\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ANSIBLE_ARGS_FILE", argsPath)

	if err := run(context.Background(), "ansible/site.yml", "/tmp/site/generated/ansible/inventory.ini", []byte("{}"), "lab-fw-01"); err != nil {
		t.Fatal(err)
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
		"boetticher_credential_dropin_install is changed",
		"pulse_service_state.stdout_lines | default([]) != ['active', 'running']",
		"state: restarted",
		"daemon_reload: true",
	} {
		if !strings.Contains(monitorText, required) {
			t.Fatalf("Pulse recovery contract is missing %q", required)
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

func TestEndpointTLSKeysAreGeneratedLocallyAndNeverSuppliedByController(t *testing.T) {
	for _, role := range []string{"monitor", "portal"} {
		path := filepath.Join("..", "..", "ansible", "roles", role, "tasks", "main.yml")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		if !strings.Contains(text, "openssl\n") || !strings.Contains(text, "genpkey") || !strings.Contains(text, "Restrict the "+role+" endpoint private key") {
			t.Fatalf("%s role does not generate and restrict its endpoint key locally", role)
		}
		if strings.Contains(text, role+"_server_key_pem") {
			t.Fatalf("%s role still accepts a controller-supplied endpoint private key", role)
		}
		if !strings.Contains(text, "ansible.builtin.fetch:") || !strings.Contains(text, role+".csr.pem") {
			t.Fatalf("%s role does not return its CSR to the controller", role)
		}
	}
	portal, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "portal", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(portal), "Enable and reload the portal nginx service") || !strings.Contains(string(portal), "state: reloaded") {
		t.Fatal("portal role does not enable and reload nginx after installing its certificate")
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
	if !strings.Contains(text, "path: \"{{ logging_plan.remote_journal_path }}\"\n    state: directory\n    owner: root\n    group: systemd-journal-remote\n    mode: '2770'") || !strings.Contains(text, "Grant the managed administrator read access to collected journals") || !strings.Contains(text, "groups: systemd-journal-remote\n    append: true") || !strings.Contains(text, "path: /var/lib/boetticher/identity/logging/collector.key") || !strings.Contains(text, "group: systemd-journal-remote\n    mode: '0640'") {
		t.Fatal("logging collector private key is not readable by the systemd-journal-remote service user")
	}
}

func TestLoggingUploadKeyIsReadableByItsServiceGroup(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "base", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "Create endpoint-local logging identity directory") || !strings.Contains(text, "group: systemd-journal\n    mode: '0750'") || !strings.Contains(text, "Allow the upload service to read its private key") || !strings.Contains(text, "group: systemd-journal\n    mode: '0640'") {
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
	for _, expected := range []string{
		"Allow endpoint services to traverse the boetticher runtime state path",
		"path: /var/lib/boetticher",
		"group: systemd-journal",
		"mode: '0751'",
		"Allow endpoint services to traverse the boetticher identity path",
		"path: /var/lib/boetticher/identity",
		"when: inventory_hostname in logging_upload_configs",
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
		"- name: Configure Chrony for unprivileged appliances",
		"content: \"DAEMON_OPTS=\\\"-x\\\"\\n\"",
		"dest: /etc/default/chrony",
		"when: inventory_hostname not in groups.get('proxmox', [])",
		"- name: Allow Chrony startup without kernel clock control",
		"path: /etc/systemd/system/chrony.service.d",
		"state: directory",
		"- name: Install Chrony startup override",
		"content: \"[Unit]\\nConditionCapability=\\n\"",
		"dest: /etc/systemd/system/chrony.service.d/boetticher.conf",
		"notify: reload systemd",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("base role missing %q", expected)
		}
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
	for _, expected := range []string{"pdnsutil list-all-zones", "pdnsutil create-zone", "pdnsutil replace-rrset", "pdnsutil delete-rrset", "pdnsutil set-meta", "pdnsutil create-secondary-zone", "replace-rrset {{ item }} @ NS", "item.name | replace('.' ~ dns_plan.static_zone, '')", "item.value"} {
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
	for _, required := range []string{"Allow Blocky to traverse its non-secret filtering policy path", "path: /etc/boetticher", "mode: '0755'", "dns_plan.recursive_provider == 'blocky'"} {
		if !strings.Contains(text, required) {
			t.Fatalf("DNS role is missing Blocky filtering traversal contract %q", required)
		}
	}
}

func TestPowerDNSTemplateUsesCurrentPrimarySecondarySettings(t *testing.T) {
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
	for _, expected := range []string{"secondary=", "primary="} {
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
	for _, expected := range []string{"monitor_server_cert_pem", "client_ca_pem", "ssl_verify_client optional", "if ($ssl_client_verify != SUCCESS) { return 403; }", "proxy_pass http://127.0.0.1:7655"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("monitoring role missing TLS/frontend contract %q", expected)
		}
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
		`upstreams:\n    groups:\n        default:`,
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("Ansible variables missing %q", expected)
		}
	}
	if strings.Contains(text, "c2VjcmV0") {
		t.Fatal("generated Ansible variables contain secret material")
	}
}

func TestVariablesDoNotRenderBlockyForAdGuardSites(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	site.ModuleConfig = map[string]model.ModuleConfig{"dns": {Provider: string(model.DNSProviderAdGuard)}}
	variables, err := Variables(site)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(variables), "upstreams:\n") {
		t.Fatal("AdGuard variables unexpectedly contain Blocky configuration")
	}
	if !strings.Contains(string(variables), `"recursive_provider": "adguard"`) {
		t.Fatal("AdGuard provider was not retained in the generated DNS plan")
	}
}

func TestDNSAppliancePathCannotInstallAResolver(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "dns", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, forbidden := range []string{"ansible.builtin.get_url:", "ansible.builtin.unarchive:", "AdGuardHome_linux_amd64.tar.gz"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("DNS role retains software installation path %q", forbidden)
		}
	}
	if !strings.Contains(text, "Require the qualified AdGuard binary in an appliance") || !strings.Contains(text, "/opt/AdGuardHome/AdGuardHome --version") {
		t.Fatal("AdGuard appliance path does not assert that the selected binary is image-provided")
	}
}

func TestApplianceRolesDoNotMutateModuleSoftware(t *testing.T) {
	for _, role := range []string{"dns", "monitor", "firewall", "logging", "portal"} {
		path := filepath.Join("..", "..", "ansible", "roles", role, "tasks", "main.yml")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		for _, forbidden := range []string{"ansible.builtin.apt:", "ansible.builtin.apt_repository:", "ansible.builtin.get_url:", "ansible.builtin.unarchive:"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s appliance role retains software mutation task %q", role, forbidden)
			}
		}
		if !strings.Contains(text, "boetticher_appliance_artifact") {
			t.Fatalf("%s appliance role does not require the qualified artifact path", role)
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
				"--accept-dns=false",
				"--advertise-routes=10.10.0.0/16",
				"--snat-subnet-routes=true",
			},
			forbidden: []string{"advertise-exit-node", "privileged: true", "ansible.builtin.apt:"},
		},
		{
			role: "litellm",
			required: []string{
				"boetticher_appliance_artifact",
				"no_log: true",
				"dest: /usr/lib/boetticher/litellm-start",
				"group: litellm",
				"ssl_verify_client on;",
				"proxy_pass http://127.0.0.1:4000;",
				"listen 10.10.20.60:443 ssl;",
				"proxy_pass http://127.0.0.1:4000;",
			},
			forbidden: []string{"listen 10.10.20.60:80", "api_key: {{", "ansible.builtin.get_url:"},
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
