package ansible

import (
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
		"lab-dns-01 ansible_host=10.10.20.10",
		"ProxyJump=lab-bastion",
		"HostKeyAlias=lab-dns-01.lab.home.arpa",
		"[managed:children]",
	} {
		if !strings.Contains(first, expected) {
			t.Errorf("inventory missing %q", expected)
		}
	}
}

func TestAgent2IsEnabledOnEveryManagedLinuxHost(t *testing.T) {
	path := filepath.Join("..", "..", "ansible", "roles", "monitor", "tasks", "main.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "groups.get('portal', []) + ['lab-monitor-01']") {
		t.Fatal("portal is not included in the managed Agent 2 service condition")
	}
	if !strings.Contains(text, "groups.get('firewall', []) + groups.get('portal', []) + ['lab-monitor-01']") {
		t.Fatal("managed firewall is not included in the Agent 2 service condition")
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
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("Ansible variables missing %q", expected)
		}
	}
	if strings.Contains(text, "c2VjcmV0") {
		t.Fatal("generated Ansible variables contain secret material")
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
	if !strings.Contains(text, "stdin: >-") || !strings.Contains(text, "INSERT OR REPLACE INTO tsigkeys") {
		t.Fatal("DNS role does not provide TSIG material through protected sqlite3 stdin")
	}
	if strings.Contains(text, "pdnsutil\n      - tsigkey\n      - import") || strings.Contains(text, "- \"{{ ddns_tsig_secret }}\"") {
		t.Fatal("DNS role still places the TSIG secret in a process argument")
	}
	if !strings.Contains(text, "no_log: true") {
		t.Fatal("DNS role does not suppress secret-bearing task output")
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
		if strings.HasPrefix(line, "local-address=") && strings.Contains(line, "10.10.20.10") {
			t.Fatal("PowerDNS local listener hard-codes the primary address for both DNS guests")
		}
	}
}
