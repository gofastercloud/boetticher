package ansible

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAirVPNPeerTemplateRendersOnlyEnabledReservation(t *testing.T) {
	binary, err := exec.LookPath("ansible-playbook")
	if err != nil {
		t.Skip("ansible-playbook is required for template integration tests")
	}
	source, err := filepath.Abs(filepath.Join("..", "..", "ansible", "roles", "airvpn", "templates", "airvpn.nft.j2"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var playbook strings.Builder
	for i, setting := range []struct {
		port    int
		sources string
	}{{45678, "['10.10.20.110/32']"}, {0, "['10.10.20.110/32']"}, {45678, "[]"}} {
		fmt.Fprintf(&playbook, `- hosts: localhost
  connection: local
  gather_facts: false
  vars:
    module_configs:
      airvpn: {qbittorrent_port: %d}
    firewall_plan:
      airvpn_source_cidrs: %s
      airvpn: {endpoint_addresses: ['198.51.100.1'], endpoint_port: 1637}
    firewall_non_public_ipv4: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
    dns_plan: {nameservers: ['10.10.10.10']}
  tasks:
    - ansible.builtin.template:
        src: %q
        dest: %q
        mode: '0600'
`, setting.port, setting.sources, source, filepath.Join(dir, fmt.Sprintf("rules-%d", i)))
	}
	path := filepath.Join(dir, "render.yml")
	if err := os.WriteFile(path, []byte(playbook.String()), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-i", "localhost,", path)
	cmd.Env = append(os.Environ(), "ANSIBLE_LOCAL_TEMP="+filepath.Join(dir, "local"), "ANSIBLE_REMOTE_TEMP="+filepath.Join(dir, "remote"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("render AirVPN template: %v\n%s", err, out)
	}
	for i := range 3 {
		data, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("rules-%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		for _, rule := range []string{
			`iifname "airvpn0" meta l4proto { tcp, udp } th dport 45678 dnat to 10.10.20.110`,
			`iifname "airvpn0" oifname "eth0" ip daddr 10.10.20.110 meta l4proto { tcp, udp } th dport 45678 ct status dnat accept`,
			`ct status dnat snat to 10.10.5.20`,
		} {
			if strings.Contains(text, rule) != (i == 0) {
				t.Fatalf("case %d has incorrect forwarding rule %q", i, rule)
			}
		}
		if !strings.Contains(text, `iifname "eth0" oifname "eth0" drop`) {
			t.Fatal("forwarding lost the direct-path kill switch")
		}
	}
}
