package cli

import (
	"bytes"
	"context"
	"errors"
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

func TestPublishedServicesActivateAtTheEndOfDNSModule(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "internal", "cli", "converge.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	publicationActivation := strings.Index(text, `if module == "dns" && s.Gateway.Mode == model.GatewayModeManaged && len(firewallPlan.Publications) > 0`)
	allHostsConvergence := strings.Index(text, `if err := ansible.Run(ctx, ansiblePlaybook, inventoryPath, variables); err != nil`)
	if publicationActivation < 0 || allHostsConvergence < 0 || publicationActivation > allHostsConvergence {
		t.Fatal("published services are not activated immediately after the DNS module")
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

func TestPortalSourceDirectoryIsAbsoluteForAnsible(t *testing.T) {
	got, err := absolutePortalSourceDir("relative-site")
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(got) || !strings.HasSuffix(got, filepath.Join("relative-site", "generated", "portal")) {
		t.Fatalf("portal source directory = %q, want absolute generated portal path", got)
	}
}

func TestLoadProxmoxClientRejectsInvalidBootstrapBeforeCredentials(t *testing.T) {
	s := model.NewDefaultSite("installation", "age1example")
	s.BootstrapAddress = "proxmox.example"
	_, _, err := loadProxmoxClientWithSnippetUser(t.TempDir(), s, "/missing/age-identity", "", false, "root")
	if err == nil || !strings.Contains(err.Error(), "IPv4") {
		t.Fatalf("invalid bootstrap address was not rejected before credential loading: %v", err)
	}
}

func TestProjectionCleanupRejectsSymlinkedGeneratedRoot(t *testing.T) {
	dir := t.TempDir()
	external := t.TempDir()
	sentinel := filepath.Join(external, "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(dir, "generated")); err != nil {
		t.Fatal(err)
	}
	if err := writeModelProjections(dir, model.NewDefaultSite("installation", "age1example")); err == nil {
		t.Fatal("projection cleanup accepted a symlinked generated root")
	}
	got, readErr := os.ReadFile(sentinel)
	if readErr != nil || string(got) != "keep" {
		t.Fatalf("external projection sentinel changed: %q, %v", got, readErr)
	}
}

func TestProjectionCleanupRejectsSymlinkedModuleRoot(t *testing.T) {
	dir := t.TempDir()
	moduleRootParent := filepath.Join(dir, "generated")
	if err := os.MkdirAll(moduleRootParent, 0700); err != nil {
		t.Fatal(err)
	}
	external := t.TempDir()
	sentinel := filepath.Join(external, "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(moduleRootParent, "modules")); err != nil {
		t.Fatal(err)
	}
	if err := writeModelProjections(dir, model.NewDefaultSite("installation", "age1example")); err == nil {
		t.Fatal("projection cleanup accepted a symlinked module root")
	}
	got, readErr := os.ReadFile(sentinel)
	if readErr != nil || string(got) != "keep" {
		t.Fatalf("external module projection sentinel changed: %q, %v", got, readErr)
	}
}

func TestEndpointClientTrustProjectionIncludesRootAndIssuingCAs(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "internal", "cli", "converge.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "runtimeVariables[\"client_ca_pem\"] = authority.RootCertPEM + authority.IssuingCertPEM") {
		t.Fatal("endpoint mTLS trust projection does not include the complete platform CA chain")
	}
}

func TestPulseCredentialBootstrapUsesTemporaryRootAuthority(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "internal", "cli", "converge.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `CreatePulseMonitoringCredentials(ctx, rootRunner, s.BootstrapAddress, "root")`) {
		t.Fatal("Pulse Proxmox credential bootstrap does not use the temporary root authority")
	}
	if strings.Contains(text, `CreatePulseMonitoringCredentials(context.Background(), proxmoxRunner, s.BootstrapAddress, model.DefaultAdminSSHUser)`) {
		t.Fatal("Pulse Proxmox credential bootstrap depends on durable labadmin sudo")
	}
}

func TestDeploymentRearmsCleanedGuestRootTransportThroughHost(t *testing.T) {
	hostRunner := &deploymentRootTestRunner{hostOutput: []byte("{\"exitcode\":0,\"exited\":1,\"out-data\":\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\n\"}")}
	guestRunner := &deploymentRootTestRunner{guestErr: errors.New("permission denied"), guestSuccessAfter: 1}
	guest := proxmox.GuestPlan{VMID: model.ProxmoxVMID, Name: "lab-fw-01", Hostname: "lab-fw-01", Kind: proxmox.KindQEMU, Address: "10.10.99.1"}
	if err := waitForDeploymentRoot(context.Background(), hostRunner, "192.0.2.10", guestRunner, guest, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA operator", filepath.Join(t.TempDir(), "known_hosts"), "lab-fw-01.lab.home.arpa"); err != nil {
		t.Fatal(err)
	}
	if hostRunner.calls != 2 || guestRunner.calls != 2 || !strings.Contains(hostRunner.lastCommand, "/usr/sbin/qm guest exec 100") {
		t.Fatalf("deployment root re-arm calls = host:%d guest:%d command:%q", hostRunner.calls, guestRunner.calls, hostRunner.lastCommand)
	}
}

func TestDeploymentRetriesTransientGuestRootRearmFailure(t *testing.T) {
	hostRunner := &deploymentRootTestRunner{hostOutputs: [][]byte{[]byte("guest agent is not ready"), []byte("{\"exitcode\":0,\"exited\":1,\"out-data\":\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\n\"}")}}
	guestRunner := &deploymentRootTestRunner{guestErr: errors.New("permission denied"), guestSuccessAfter: 1}
	guest := proxmox.GuestPlan{VMID: model.ProxmoxVMID, Name: "lab-fw-01", Hostname: "lab-fw-01", Kind: proxmox.KindQEMU, Address: "10.10.99.1"}
	if err := waitForDeploymentRoot(context.Background(), hostRunner, "192.0.2.10", guestRunner, guest, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA operator", filepath.Join(t.TempDir(), "known_hosts"), "lab-fw-01.lab.home.arpa"); err != nil {
		t.Fatal(err)
	}
	if hostRunner.calls != 3 || guestRunner.calls != 2 {
		t.Fatalf("transient deployment root re-arm calls = host:%d guest:%d", hostRunner.calls, guestRunner.calls)
	}
}

func TestDeploymentWaitsForGuestHostKeyThroughBootWindow(t *testing.T) {
	hostRunner := &deploymentRootTestRunner{hostOutputs: [][]byte{
		[]byte("guest agent is not ready"),
		[]byte("guest agent is not ready"),
		[]byte("guest agent is not ready"),
		[]byte("{\"exitcode\":0,\"exited\":1,\"out-data\":\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\n\"}"),
	}}
	guestRunner := &deploymentRootTestRunner{}
	guest := proxmox.GuestPlan{VMID: model.ProxmoxVMID, Name: "lab-fw-01", Hostname: "lab-fw-01", Kind: proxmox.KindQEMU, Address: "10.10.99.1"}
	if err := waitForDeploymentRoot(context.Background(), hostRunner, "192.0.2.10", guestRunner, guest, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA operator", filepath.Join(t.TempDir(), "known_hosts"), "lab-fw-01.lab.home.arpa"); err != nil {
		t.Fatal(err)
	}
	if hostRunner.calls != 4 {
		t.Fatalf("guest host-key boot window stopped after %d attempts, want 4", hostRunner.calls)
	}
}

type deploymentRootTestRunner struct {
	calls             int
	lastCommand       string
	hostOutput        []byte
	hostOutputs       [][]byte
	guestErr          error
	guestSuccessAfter int
}

func (r *deploymentRootTestRunner) Run(_ context.Context, _ string, _ string, command string) ([]byte, error) {
	r.calls++
	r.lastCommand = command
	if len(r.hostOutputs) > 0 {
		index := r.calls - 1
		if index >= len(r.hostOutputs) {
			index = len(r.hostOutputs) - 1
		}
		return r.hostOutputs[index], nil
	}
	if r.hostOutput != nil {
		return r.hostOutput, nil
	}
	if r.calls <= r.guestSuccessAfter {
		return nil, r.guestErr
	}
	return nil, nil
}

func TestPulseReconciliationForwardUsesRestrictedBastion(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "internal", "cli", "converge.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, required := range []string{`HostAlias:     "lab-bastion"`, `StartLocalForward(ctx, s.BootstrapAddress, "lab-jump", "10.10.10.20", 443)`} {
		if !strings.Contains(text, required) {
			t.Fatalf("Pulse reconciliation does not use the restricted bastion contract %q", required)
		}
	}
	if strings.Contains(text, `StartLocalForward(context.Background(), s.BootstrapAddress, "root", "10.10.10.20", 443)`) {
		t.Fatal("Pulse reconciliation still uses the deployment-only root forwarding path")
	}
}

func TestPulseReadTokenRecoveryIsBoundedToUnauthorizedResponses(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "internal", "cli", "converge.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, required := range []string{
		"readTokenRefreshed := false",
		"pulse.IsUnauthorized(err)",
		"pulseAdmin.CreateReadToken(ctx, \"boetticher monitoring read\")",
		"site.StorePlatformSecret(*siteDir, s, *ageIdentity, \"pulse_api_token\", readToken)",
		"verify Pulse state summary after read-token refresh",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("Pulse read-token recovery is missing %q", required)
		}
	}
}

func TestPulseUsesTheProxmoxCertificateHostname(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "internal", "cli", "converge.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `Name: model.LogicalProxmoxIdentity, Host: "https://proxmox:8006"`) {
		t.Fatal("Pulse reconciliation does not use the hostname covered by the default Proxmox certificate")
	}
	if !strings.Contains(string(data), `PreviousHost: "https://proxmox." + s.Network.Domain + ":8006"`) {
		t.Fatal("Pulse reconciliation does not constrain the endpoint migration to the previous canonical hostname")
	}
}

func TestRuntimeBoundaryAcceptsRelativeSiteDirectory(t *testing.T) {
	site := model.NewDefaultSite("trial", "age1trial")
	if err := checkRuntimeBoundary("relative-site", site); err != nil {
		t.Fatalf("relative site directory rejected: %v", err)
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
	if err := verifyDNSReadiness(context.Background(), runner, "10.10.10.10"); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("readiness commands = %d, want 1", len(runner.commands))
	}
	command := runner.commands[0]
	for _, required := range []string{
		"systemctl is-active pdns chrony blocky",
		"blocky version | grep -Fq '0.34.0'",
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
		"10.10.30.1/24",
		"servers0",
		"10.10.20.1/24",
		"sandbox0",
		"10.10.40.1/24",
		"mgmt0",
		"10.10.99.1/24",
		"transit0",
		"10.10.5.1/24",
		"infra0",
		"10.10.10.1/24",
	} {
		if !strings.Contains(command, required) {
			t.Fatalf("firewall bootstrap network check omitted %q: %s", required, command)
		}
	}
	if strings.Contains(command, "sudo -n ip") {
		t.Fatalf("read-only bootstrap network probes unnecessarily require sudo: %s", command)
	}
}
