package cli

import (
	"strings"
	"testing"
)

func TestProviderDHCPConfigReadbackRequiresIgnoredHomeSection(t *testing.T) {
	for _, test := range []struct {
		name, config string
		wantErr      bool
	}{
		{name: "disabled", config: "config dhcp 'boetticher_home'\n\toption ignore '1'\n", wantErr: false},
		{name: "enabled", config: "config dhcp 'boetticher_home'\n\toption ignore '0'\n", wantErr: true},
		{name: "shared client services", config: "config dnsmasq 'boetticher_dnsmasq'\nconfig dhcp 'boetticher_home'\n\toption ignore '1'\nconfig dhcp 'boetticher_dhcp_servers'\n", wantErr: false},
		{name: "unexpected dnsmasq", config: "config dhcp 'boetticher_home'\n\toption ignore '1'\nconfig dnsmasq 'factory'\n", wantErr: true},
		{name: "unexpected dhcp scope", config: "config dhcp 'boetticher_home'\n\toption ignore '1'\nconfig dhcp 'factory'\n", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := validateProviderDHCPConfig(test.config); got != nil != test.wantErr {
				t.Fatalf("validateProviderDHCPConfig() error = %v, wantErr=%t", got, test.wantErr)
			}
		})
	}
}

func TestParseFirewallTestOptionsRejectsContradictoryFlags(t *testing.T) {
	for _, args := range [][]string{
		{"--plan", "--yes"},
		{"--plan", "--cleanup-only"},
		{"--cleanup-only"},
		{"--insecure"},
		{"--site", "/tmp/site"},
	} {
		if _, err := parseFirewallTestOptions(args); err == nil {
			t.Fatalf("firewall test options %v were accepted", args)
		}
	}
}

func TestParseFirewallTestOptionsAcceptsOnlySupportedForms(t *testing.T) {
	for _, args := range [][]string{{"--plan"}, {"--yes"}, {"--cleanup-only", "--yes"}} {
		if _, err := parseFirewallTestOptions(args); err != nil {
			t.Fatalf("firewall test options %v failed: %v", args, err)
		}
	}
}

func TestFirewallPlanAndStatusRejectApprovalFlags(t *testing.T) {
	for _, command := range []string{"module firewall plan", "module firewall status"} {
		if _, err := parseFirewallOptions(command, []string{"--yes"}, false); err == nil {
			t.Fatalf("%s accepted meaningless --yes", command)
		}
	}
	if options, err := parseFirewallOptions("module firewall apply", []string{"--yes"}, true); err != nil || !options.yes {
		t.Fatalf("apply did not accept --yes: options=%#v err=%v", options, err)
	}
}

func TestFirewallTeardownPreviewRejectsApproval(t *testing.T) {
	if _, err := parseFirewallTeardownOptions([]string{"--plan", "--yes"}); err == nil || !strings.Contains(err.Error(), "--plan") {
		t.Fatalf("teardown preview approval was accepted: %v", err)
	}
}

func TestRetiredNetworkTestPointsToFirewallCapability(t *testing.T) {
	err := retiredCommandError([]string{"network", "test"})
	if err == nil || !strings.Contains(err.Error(), "module firewall test") {
		t.Fatalf("legacy network test did not return migration hint: %v", err)
	}
}
