package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/site"
)

func TestAccessDescribesSupportedApplianceManagementBoundary(t *testing.T) {
	siteDir := t.TempDir()
	if err := site.SaveConfig(siteDir, model.ConfigFromSite(model.NewDefaultSite("installation", "age1example"))); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runAccess([]string{"--site", siteDir}, &output); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, want := range []string{
		"boetticher CLI",
		"generated portal/status surfaces",
		"native product UI/API",
		"Proxmox console/exec",
		"Core SSH      internal controller transport only",
		"Core         routine SSH and hand mutation are unsupported",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("access output missing %q: %s", want, text)
		}
	}
	if strings.Contains(text, "ssh firewall") || strings.Contains(text, "ssh dns") || strings.Contains(text, "ssh monitor") || strings.Contains(text, "ssh portal") {
		t.Fatalf("access output presents routine appliance SSH: %s", text)
	}
}

func TestAccessKeepsExternalFirewallOperatorManaged(t *testing.T) {
	siteDir := t.TempDir()
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeExternal))
	disabled := false
	config.Modules.Firewall = &model.FirewallModuleConfig{Enabled: &disabled}
	if err := site.SaveConfig(siteDir, config); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runAccess([]string{"--site", siteDir}, &output); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, want := range []string{"External      operator-managed appliance and recovery", "External     configure and recover through the operator's appliance", "Appliance   operator managed"} {
		if !strings.Contains(text, want) {
			t.Errorf("external access output missing %q: %s", want, text)
		}
	}
	if strings.Contains(text, "routine SSH and hand mutation are unsupported") {
		t.Fatalf("external access output applies Core-only prohibition to operator appliance: %s", text)
	}
}

func TestPreferredAccessAliasUsesCanonicalNumberedDNSAlias(t *testing.T) {
	component := model.Component{Name: "lab-dns-01", DNSAliases: []string{"dns", "dns01"}}
	if got := preferredAccessAlias(component); got != "dns01" {
		t.Fatalf("preferredAccessAlias() = %q, want dns01", got)
	}
}
