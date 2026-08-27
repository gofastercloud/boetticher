package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	"github.com/gofastercloud/boetticher/internal/proxmox"
)

type dnsReadinessRunner struct {
	commands []string
}

func (r *dnsReadinessRunner) Run(_ context.Context, _ string, _ string, command string) ([]byte, error) {
	r.commands = append(r.commands, command)
	return nil, nil
}

func TestDeploymentModuleNamesFollowResolvedManagedGraph(t *testing.T) {
	resolved, _, err := modules.Compose(model.ConfigFromSite(model.NewSite("trial", "age1trial", model.GatewayModeManaged)))
	if err != nil {
		t.Fatal(err)
	}
	got := deploymentModuleNames(resolved)
	want := []string{"dns", "logging", "monitoring", "portal"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("managed deployment order = %v, want %v", got, want)
	}
}

func TestAnsiblePlaybookIsAvailableFromControllerSource(t *testing.T) {
	root, err := applianceBuildSourceRoot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "ansible", "site.yml")); err != nil {
		t.Fatalf("controller source does not contain the Ansible playbook: %v", err)
	}
}

func TestDeploymentModuleNamesFollowResolvedExternalGraph(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("trial", "age1trial", model.GatewayModeExternal))
	disabled := false
	config.Modules.Firewall = &model.ToggleModuleConfig{Enabled: &disabled}
	resolved, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	got := deploymentModuleNames(resolved)
	want := []string{"dns", "logging", "monitoring", "portal"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("external deployment order = %v, want %v", got, want)
	}
}

func TestArtifactQualificationStatusDistinguishesDefinitionAndContent(t *testing.T) {
	artifact := model.Artifact{Name: "boetticher-dns-blocky"}
	if got := artifactQualificationStatus(artifact); got != "NOT BUILT (qualified content evidence absent)" {
		t.Fatalf("unqualified artifact status = %q", got)
	}
	artifact.ContentSHA256 = strings.Repeat("b", 64)
	if got := artifactQualificationStatus(artifact); got != "QUALIFIED content="+artifact.ContentSHA256 {
		t.Fatalf("qualified artifact status = %q", got)
	}
}

func TestDeployDryRunDoesNotWriteLocalProjections(t *testing.T) {
	siteDir := t.TempDir()
	config := model.ConfigFromSite(model.NewDefaultSite("trial", "age1trial"))
	data, err := model.RenderSiteConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(siteDir, "site.yml"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runDeploy([]string{"--site", siteDir, "--dry-run"}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Artifact qualification: HOLD") {
		t.Fatalf("dry-run omitted missing qualification hold: %s", output.String())
	}
	if _, err := os.Stat(filepath.Join(siteDir, "generated", "model.json")); !os.IsNotExist(err) {
		t.Fatalf("deploy dry-run wrote a local model projection: %v", err)
	}
}

func TestResolvedArtifactContentReachesRuntimeDeclaration(t *testing.T) {
	declaration := model.ModuleDeclaration{Module: "dns", Artifact: model.Artifact{
		Name: "boetticher-dns-blocky", Version: "1.0.0", Kind: "lxc", Architecture: "amd64", DefinitionSHA256: strings.Repeat("a", 64),
	}}
	guest := proxmox.GuestPlan{VMID: model.DNS01VMID, Name: "lab-dns-01", Owner: "boetticher/module/dns", Artifact: model.Artifact{
		Name: "boetticher-dns-blocky", Version: "1.0.0", Kind: "lxc", Architecture: "amd64", DefinitionSHA256: strings.Repeat("a", 64), ContentSHA256: strings.Repeat("b", 64),
	}}
	resolved, err := resolvedDeclarationForGuest(declaration, guest)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Artifact.ContentSHA256 != guest.Artifact.ContentSHA256 {
		t.Fatalf("resolved content digest = %q, want %q", resolved.Artifact.ContentSHA256, guest.Artifact.ContentSHA256)
	}
}

func TestRuntimeDeclarationRejectsUnqualifiedGuestArtifact(t *testing.T) {
	_, err := resolvedDeclarationForGuest(model.ModuleDeclaration{Module: "dns"}, proxmox.GuestPlan{Owner: "boetticher/module/dns"})
	if err == nil || !strings.Contains(err.Error(), "qualified artifact") {
		t.Fatalf("unqualified guest artifact was accepted: %v", err)
	}
}

func TestVerifyDNSReadinessChecksTheQualifiedBlockyRuntime(t *testing.T) {
	runner := &dnsReadinessRunner{}
	if err := verifyDNSReadiness(context.Background(), runner, "10.10.20.10", string(model.DNSProviderBlocky)); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("readiness commands = %d, want 1", len(runner.commands))
	}
	command := runner.commands[0]
	for _, required := range []string{
		"systemctl is-active pdns chrony blocky",
		"test ! -e /opt/AdGuardHome/AdGuardHome",
		"blocky --version | grep -Fq '0.34.0'",
		"blocky validate --config /etc/blocky/config.yml",
	} {
		if !strings.Contains(command, required) {
			t.Fatalf("Blocky readiness command omitted %q: %s", required, command)
		}
	}
}

func TestVerifyGatewayReadinessChecksAllGatewayServices(t *testing.T) {
	runner := &dnsReadinessRunner{}
	if err := verifyGatewayReadiness(context.Background(), runner, "10.10.99.1"); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("readiness commands = %d, want 1", len(runner.commands))
	}
	command := runner.commands[0]
	for _, required := range []string{
		"nft -c -f /etc/nftables.conf",
		"systemctl is-active nftables kea-dhcp4-server kea-dhcp-ddns-server dnsmasq chrony",
		"sysctl -n net.ipv4.ip_forward",
	} {
		if !strings.Contains(command, required) {
			t.Fatalf("gateway readiness command omitted %q: %s", required, command)
		}
	}
}

func TestVerifyFirewallBootstrapNetworkChecksStableRolesAndAddresses(t *testing.T) {
	runner := &dnsReadinessRunner{}
	if err := verifyFirewallBootstrapNetwork(context.Background(), runner); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("bootstrap network commands = %d, want 1", len(runner.commands))
	}
	command := runner.commands[0]
	for _, required := range []string{
		"ip link show dev \"$interface\"",
		"trusted0",
		"10.10.10.1/24",
		"servers0",
		"10.10.20.1/24",
		"sandbox0",
		"10.10.50.1/24",
		"mgmt0",
		"10.10.99.1/24",
	} {
		if !strings.Contains(command, required) {
			t.Fatalf("firewall bootstrap network check omitted %q: %s", required, command)
		}
	}
	if strings.Contains(command, "sudo -n ip") {
		t.Fatalf("read-only bootstrap network probes unnecessarily require sudo: %s", command)
	}
}
