package cli

import (
	"strings"
	"testing"
)

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
