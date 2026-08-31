package ansible

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

func TestStreamDeckIdentityMaterialUsesServiceOwnedPath(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "streamdeck", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, expected := range []string{
		"path: /var/lib/streamdeck/tls",
		"/var/lib/streamdeck/tls/streamdeck.key.pem",
		"/var/lib/streamdeck/tls/streamdeck.csr.pem",
		"/var/lib/streamdeck/tls/streamdeck.crt.pem",
		"/var/lib/streamdeck/tls/ca.pem",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("StreamDeck role is missing service-owned identity path %q", expected)
		}
	}
	if strings.Contains(text, "/var/lib/boetticher/identity/tls/streamdeck") {
		t.Fatal("StreamDeck role still places identity material in the shared identity tree")
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

func TestPortalServiceAllowsTheCompleteClientCertificateChain(t *testing.T) {
	service, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "portal", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"ssl_client_certificate /etc/boetticher/tls/client-ca.pem;", "ssl_crl /etc/boetticher/tls/client-ca.crl.pem;", "ssl_verify_client on;", "ssl_verify_depth 3;"} {
		if !strings.Contains(string(service), expected) {
			t.Fatalf("portal mTLS contract is missing %q", expected)
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
	if got := strings.Count(text, "if ($ssl_client_verify != SUCCESS) { return 403; }"); got != 9 {
		t.Fatalf("monitor frontend mTLS guards = %d, want the three StreamDeck routes, five exact AIOps routes, and the catch-all", got)
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
	scriptPath := filepath.Join(tempDir, "ansible-playbook")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$ANSIBLE_ARGS_FILE\"\ncat >/dev/null\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ANSIBLE_ARGS_FILE", argsPath)

	if err := run(context.Background(), "ansible/site.yml", inventoryPath, []byte("{}"), "lab-fw-01"); err != nil {
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

func TestLiteLLMRestartsWhenAnyRuntimeCredentialIsMissing(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "litellm", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, required := range []string{
		"test -s /run/credentials/litellm.service/{{ upstream.api_key_secret | lower | replace('_', '-') | replace('.', '-') }}",
		"register: litellm_runtime_credentials",
		"litellm_runtime_credentials.results | default([]) | selectattr('rc', 'ne', 0) | list | length > 0",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("LiteLLM credential recovery contract is missing %q", required)
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
		"- name: Configure Chrony for unprivileged appliances",
		"content: \"DAEMON_OPTS=\\\"-x\\\"\\n\"",
		"dest: /etc/default/chrony",
		"when: inventory_hostname not in groups.get('proxmox', [])",
		"- name: Allow Chrony startup without kernel clock control",
		"path: /etc/systemd/system/chrony.service.d",
		"state: directory",
		"- name: Install Chrony startup override",
		"content: \"[Unit]\\nAfter=network-online.target\\nWants=network-online.target\\nConditionCapability=\\n\"",
		"dest: /etc/systemd/system/chrony.service.d/boetticher.conf",
		"notify: reload systemd",
		"- name: Disable the restricted Chrony service in appliances",
		"name: chronyd-restricted.service",
		"enabled: false",
		"state: stopped",
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
	for _, expected := range []string{"pdnsutil list-all-zones", "pdnsutil create-zone", "pdnsutil set-kind {{ item }} MASTER", "pdnsutil replace-rrset", "pdnsutil delete-rrset", "pdnsutil set-meta", "NOTIFY-DNSUPDATE 1", "pdnsutil create-secondary-zone", "replace-rrset {{ item }} @ NS", "item.name | replace('.' ~ dns_plan.static_zone, '')", "item.value"} {
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
	for _, expected := range []string{"monitor_server_cert_pem", "client_ca_pem", "client_crl_pem", "ssl_crl /etc/boetticher/tls/client-ca.crl.pem", "ssl_verify_client optional", "ssl_verify_depth 3;", "if ($ssl_client_verify != SUCCESS) { return 403; }", "proxy_pass http://127.0.0.1:7655"} {
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
			},
			forbidden: []string{"advertise-exit-node", "privileged: true", "ansible.builtin.apt:", `regex_search('"BackendState"[[:space:]]*`},
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
			role: "litellm",
			required: []string{
				"boetticher_appliance_artifact",
				"no_log: true",
				"dest: /usr/lib/boetticher/litellm-start",
				"group: litellm",
				"path: /etc/boetticher/litellm",
				"mode: '0751'",
				"exec /usr/bin/setpriv --reuid=litellm --regid=litellm --init-groups /opt/litellm/bin/litellm \"$@\"",
				"ssl_verify_client on;",
				"proxy_pass http://127.0.0.1:4000;",
				"listen 10.10.20.60:443 ssl;",
				"proxy_pass http://127.0.0.1:4000;",
				"path: /etc/systemd/system/nginx.service.d",
				"dest: /etc/systemd/system/nginx.service.d/boetticher-network.conf",
				"After=network-online.target",
				"Wants=network-online.target",
				"notify: restart nginx",
				"Restart LiteLLM after credential projection or an unhealthy start",
				"systemctl show litellm --property=ActiveState --property=SubState --value",
				"daemon_reload: true",
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
		"CN=client-boetticher-reconciler.{{ domain }},O=boetticher",
		"CN=(?:lab-streamdeck-01|client-boetticher-pulse-read",
		"location = /api/health",
		"location = /api/state/summary",
		"location = /api/resources",
		"proxy_set_header X-API-Token $http_x_api_token",
		"include /run/boetticher/pulse-proxy-auth.conf",
		"set $boetticher_pulse_proxy_shared_secret",
		"set $boetticher_pulse_proxy_secret $boetticher_pulse_proxy_shared_secret",
		"proxy_set_header X-Proxy-Secret $boetticher_pulse_proxy_secret",
		"ExecStartPre=/usr/local/sbin/boetticher-pulse-nginx-proxy-auth",
		"daemon_reload: true",
	} {
		if !strings.Contains(contract, expected) {
			t.Fatalf("Pulse proxy-auth contract is missing %q", expected)
		}
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

func TestPiKioskUsesDedicatedPulseClientCertificate(t *testing.T) {
	service, err := os.ReadFile(filepath.Join("..", "..", "pi", "kiosk", "systemd", "pulse-kiosk.service"))
	if err != nil {
		t.Fatal(err)
	}
	dropIn, err := os.ReadFile(filepath.Join("..", "..", "pi", "kiosk", "systemd", "pulse-kiosk.service.d", "20-pulse-dashboard.conf"))
	if err != nil {
		t.Fatal(err)
	}
	serviceText := string(service)
	dropInText := string(dropIn)
	for _, required := range []string{
		"User=kiosk",
		"NoNewPrivileges=yes",
		"ProtectSystem=strict",
		"CapabilityBoundingSet=",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
		"https://monitor.lab.home.arpa",
	} {
		if !strings.Contains(serviceText, required) {
			t.Fatalf("Pi kiosk service is missing %q", required)
		}
	}
	for _, required := range []string{
		"ExecStart=",
		"--auto-select-certificate-for-urls=",
		"ISSUER",
		"boetticher Issuing CA",
		"client-lab-display-01-kiosk.lab.home.arpa",
		"https://monitor.lab.home.arpa",
		"--disable-extensions-except=/home/kiosk/pulse-refresh-extension",
		"--load-extension=/home/kiosk/pulse-refresh-extension",
	} {
		if !strings.Contains(dropInText, required) {
			t.Fatalf("Pi kiosk Pulse drop-in is missing %q", required)
		}
	}
	for _, text := range []string{serviceText, dropInText} {
		for _, forbidden := range []string{"-----BEGIN", "private.key", "PKCS12", "X-API-Token"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("Pi kiosk source contains forbidden credential material %q", forbidden)
			}
		}
	}
	refreshManifest, err := os.ReadFile(filepath.Join("..", "..", "pi", "kiosk", "pulse-refresh-extension", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	refreshScript, err := os.ReadFile(filepath.Join("..", "..", "pi", "kiosk", "pulse-refresh-extension", "reload.js"))
	if err != nil {
		t.Fatal(err)
	}
	manifestText := string(refreshManifest)
	scriptText := string(refreshScript)
	for _, required := range []string{"manifest_version", "content_scripts", "https://monitor.lab.home.arpa/*", "reload.js"} {
		if !strings.Contains(manifestText, required) {
			t.Fatalf("Pi kiosk refresh extension is missing %q", required)
		}
	}
	if !strings.Contains(scriptText, "30_000") || !strings.Contains(scriptText, "window.location.replace(window.location.href)") {
		t.Fatal("Pi kiosk refresh extension does not reload after 30 seconds")
	}
	for _, forbidden := range []string{"<all_urls>", "permissions", "host_permissions", "X-API-Token", "-----BEGIN"} {
		if strings.Contains(manifestText+scriptText, forbidden) {
			t.Fatalf("Pi kiosk refresh extension contains forbidden capability or credential material %q", forbidden)
		}
	}
}
