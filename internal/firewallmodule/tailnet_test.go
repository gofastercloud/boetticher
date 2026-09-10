package firewallmodule

import (
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/openwrt"
)

func TestDiffFirewallIgnoresForeignSafetyIPSet(t *testing.T) {
	desired := tailnetFirewallSections("192.168.4.0/22")
	current := make(map[string]openwrt.UCISection, len(desired)+1)
	for _, section := range desired {
		current[section.Name] = openwrt.UCISection{Type: section.Type, Options: section.Options, Lists: section.Lists}
	}
	current["boetticher_4c_safety_ipset"] = openwrt.UCISection{Type: "ipset", Options: map[string]string{"family": "ipv4"}, Lists: map[string][]string{}}
	got, err := DiffFirewall(current, desired)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("foreign safety ipset created false firewall drift: %#v", got)
	}
	wrong := make(map[string]openwrt.UCISection, len(current))
	for name, section := range current {
		wrong[name] = section
	}
	wrong[desired[0].Name] = openwrt.UCISection{Type: desired[0].Type, Options: map[string]string{
		"name": "Boetticher Tailnet deny_home", "src": "transit", "src_ip": "10.10.5.11/32", "src_mac": "02:00:00:00:05:10", "family": "ipv4", "target": "DROP",
	}, Lists: desired[0].Lists}
	if _, err := DiffFirewall(wrong, desired); err == nil {
		t.Fatal("wrong Tailnet source identity was accepted")
	}

	teardown, err := DiffFirewall(current, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range teardown {
		if change.Section.Name == "boetticher_4c_safety_ipset" {
			t.Fatal("foreign safety ipset was scheduled for teardown")
		}
	}
}

func TestTailnetProxmoxSSHRuleIsExact(t *testing.T) {
	for _, section := range tailnetFirewallSections("192.168.4.0/22") {
		if section.Name != "boetticher_tailnet_proxmox_ssh" {
			continue
		}
		if section.Options["dest"] != "mgmt" || section.Options["dest_ip"] != model.ProxmoxManagementAddress+"/32" || section.Options["proto"] != "tcp" || section.Options["dest_port"] != "22" {
			t.Fatalf("Tailnet Proxmox SSH rule is broader than required: %#v", section.Options)
		}
		return
	}
	t.Fatal("Tailnet Proxmox SSH rule missing")
}

func TestTailnetTransportAllowsControlFallbackPorts(t *testing.T) {
	for _, section := range tailnetFirewallSections("192.168.4.0/22") {
		if section.Name == "boetticher_tailnet_transport_tcp" {
			if got := section.Options["dest_port"]; got != "80 443" {
				t.Fatalf("Tailnet TCP transport ports = %q, want 80 443", got)
			}
			return
		}
	}
	t.Fatal("Tailnet TCP transport rule missing")
}

func TestTailnetSSHToManagementIsNarrowAndIdentityBound(t *testing.T) {
	sections := tailnetFirewallSections("192.168.4.0/22")
	for _, section := range sections {
		if section.Name != "boetticher_tailnet_proxmox_ssh" {
			continue
		}
		if section.Options["src"] != "transit" || section.Options["src_ip"] != "10.10.5.10/32" || section.Options["src_mac"] != "02:00:00:00:05:10" || section.Options["dest"] != "mgmt" || section.Options["proto"] != "tcp" || section.Options["dest_port"] != "22" {
			t.Fatalf("Tailnet management SSH rule is not narrowly bound: %#v", section)
		}
		for _, other := range sections {
			if other.Type == "forwarding" {
				t.Fatalf("Tailnet SSH allowance introduced zone forwarding: %#v", other)
			}
		}
		return
	}
	t.Fatal("Tailnet management SSH rule missing")
}
