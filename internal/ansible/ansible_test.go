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
		"lab-proxmox-01 ansible_host=10.10.99.250",
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
	if strings.Contains(inventory, "lab-proxmox-01 ansible_host=10.10.99.250") {
		t.Fatal("Proxmox inventory used the internal management address for controller transport")
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

func TestMonitoringApplianceUsesImageProvidedAgent2(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "monitor", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "Require an immutable monitoring appliance artifact") {
		t.Fatal("monitoring does not require an immutable appliance artifact")
	}
	if !strings.Contains(text, "- zabbix-agent2") || !strings.Contains(text, "Enable monitoring services") {
		t.Fatal("monitoring appliance does not enable its image-provided Agent 2 service")
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
	if !strings.Contains(string(portal), "Enable and start the portal nginx service") {
		t.Fatal("portal role does not enable and start nginx after installing its certificate")
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
	for _, expected := range []string{"pdnsutil list-all-zones", "pdnsutil create-zone", "pdnsutil replace-rrset", "pdnsutil set-meta", "pdnsutil create-secondary-zone"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("DNS role missing qualified PowerDNS command %q", expected)
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

func TestMonitoringRoleUsesRunuserForDatabaseServiceUsers(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "monitor", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "become_user: postgres") || strings.Contains(text, "become_user: zabbix") {
		t.Fatal("monitoring role uses Ansible's unprivileged secondary-become path")
	}
	for _, expected := range []string{
		"runuser -u postgres -- psql --dbname postgres",
		"runuser -u zabbix -- sh -c",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("monitoring role missing explicit service-user execution %q", expected)
		}
	}
}

func TestMonitoringRolePreparesPostgreSQLTLSAndCluster(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "monitor", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, expected := range []string{
		"/usr/sbin/make-ssl-cert generate-default-snakeoil",
		"creates: /etc/ssl/private/ssl-cert-snakeoil.key",
		"pg_ctlcluster --skip-systemctl-redirect",
		"$(pg_lsclusters -h)",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("monitoring role missing PostgreSQL startup prerequisite %q", expected)
		}
	}
}

func TestMonitoringRoleCreatesZabbixStateDirectory(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "monitor", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "path: /var/lib/zabbix\n    state: directory\n    owner: zabbix\n    group: zabbix\n    mode: '0750'") {
		t.Fatal("monitoring role does not create the Zabbix state directory before its schema marker")
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
