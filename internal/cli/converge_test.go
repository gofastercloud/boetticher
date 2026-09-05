package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/site"
	"github.com/gofastercloud/boetticher/internal/telemetry"
)

type dnsReadinessRunner struct {
	commands []string
}

type convergeRoundTripFunc func(*http.Request) (*http.Response, error)

func (f convergeRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
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
	got := deploymentModuleNames(resolved, "")
	want := []string{"dns", "monitoring"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("managed deployment order = %v, want %v", got, want)
	}
	scoped := deploymentModuleNames(resolved, "monitoring")
	if strings.Join(scoped, ",") != "monitoring" {
		t.Fatalf("scoped deployment order = %v, want monitoring", scoped)
	}
}

func TestInspectDeploymentGuestStatesUsesBoundedParallelReadPool(t *testing.T) {
	var active, maximum int32
	transport := convergeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if !strings.HasSuffix(r.URL.Path, "/config") {
			t.Fatalf("unexpected guest preflight path: %s", r.URL.Path)
		}
		if strings.Contains(r.URL.Path, "/qemu/") {
			return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"errors":{"vmid":"not found"}}`))}, nil
		}
		current := atomic.AddInt32(&active, 1)
		for {
			seen := atomic.LoadInt32(&maximum)
			if current <= seen || atomic.CompareAndSwapInt32(&maximum, seen, current) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt32(&active, -1)
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"data":{}}`))}, nil
	})
	client := &proxmox.Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	guests := make([]proxmox.GuestPlan, 6)
	for index := range guests {
		guests[index] = proxmox.GuestPlan{VMID: 110 + index, Kind: proxmox.KindLXC}
	}
	report := newDeploymentReport(io.Discard)
	ctx := telemetry.WithObserver(context.Background(), report)
	states, err := inspectDeploymentGuestStates(ctx, client, "node", guests)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != len(guests) || atomic.LoadInt32(&maximum) < 2 || atomic.LoadInt32(&maximum) > 4 {
		t.Fatalf("guest preflight states=%d maximum-concurrency=%d, want six states and concurrency 2..4", len(states), maximum)
	}
}

func TestDNSInitialConfigurationOnlyRunsForNewOrReplacedGuests(t *testing.T) {
	cases := []struct {
		name  string
		state deploymentGuestArtifactState
		want  bool
	}{
		{name: "missing", state: deploymentGuestArtifactState{}, want: true},
		{name: "replaced", state: deploymentGuestArtifactState{exists: true, replacement: true}, want: true},
		{name: "unchanged", state: deploymentGuestArtifactState{exists: true}, want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := needsInitialDNSConfiguration(testCase.state); got != testCase.want {
				t.Fatalf("needsInitialDNSConfiguration(%+v) = %t, want %t", testCase.state, got, testCase.want)
			}
		})
	}
}

func TestPublishedServicesActivateAtTheEndOfDNSModule(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "internal", "cli", "converge.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	publicationActivation := strings.Index(text, `if module == "dns" && s.Gateway.Mode == model.GatewayModeManaged && len(firewallPlan.Publications) > 0`)
	allHostsConvergence := strings.Index(text, `if err := runTrackedAnsiblePhase(ctx, ansiblePlaybook, inventoryPath, variables, "", ansible.PhaseBootstrap, report, temporaryPrivateKey); err != nil`)
	if publicationActivation < 0 || allHostsConvergence < 0 || publicationActivation > allHostsConvergence {
		t.Fatal("published services are not activated immediately after the DNS module")
	}
}

func TestPublishedFirewallIsNotRepeatedInTheAllHostNetworkPhase(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "internal", "cli", "converge.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	finalFirewall := strings.Index(text, `runtimeVariables["boetticher_skip_firewall"] = true`)
	allHostsConvergence := strings.Index(text, `if err := runTrackedAnsiblePhase(ctx, ansiblePlaybook, inventoryPath, variables, "", ansible.PhaseBootstrap, report, temporaryPrivateKey); err != nil`)
	if finalFirewall < 0 || allHostsConvergence < 0 || finalFirewall > allHostsConvergence {
		t.Fatal("all-host network convergence does not skip the already published firewall")
	}
}

func TestAllHostNetworkConvergenceFollowsRuntimeReadiness(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "internal", "cli", "converge.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	allHostsConvergence := strings.Index(text, `if err := runTrackedAnsiblePhase(ctx, ansiblePlaybook, inventoryPath, variables, "", ansible.PhaseBootstrap, report, temporaryPrivateKey); err != nil`)
	gatewayReadiness := strings.Index(text, `return verifyGatewayReadiness(ctx, firewallRunner, "10.10.99.1")`)
	dnsReadiness := strings.Index(text, `return verifyDNSReadiness(ctx, guestRunner, guest.Address)`)
	if allHostsConvergence < 0 || gatewayReadiness < 0 || dnsReadiness < 0 || gatewayReadiness > allHostsConvergence || dnsReadiness > allHostsConvergence {
		t.Fatal("all-host network convergence does not follow gateway and DNS runtime readiness")
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

func TestWriteBootstrapProjectionsDefersAirVPNRuntimeProjections(t *testing.T) {
	config := model.ConfigFromSite(model.NewDefaultSite("installation", "age1example"))
	config.StorageProfile = "dedicated-data-disk"
	config.StorageDevice = "/dev/disk/by-id/ata-example-data"
	enabled := true
	config.Modules.AirVPN = &model.AirVPNModuleConfig{Enabled: &enabled, Servers: "australia"}
	config.Modules.Arr = &model.ArrModuleConfig{Enabled: &enabled, Network: model.ModuleNetworkAirVPN}
	s, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := writeBootstrapProjections(dir, s); err != nil {
		t.Fatalf("write bootstrap projections before AirVPN profile exists: %v", err)
	}
	for _, path := range []string{
		filepath.Join(dir, "generated", "model.json"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("safe bootstrap projection %s was not written: %v", path, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "generated", "firewall", "boetticher.nft")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bootstrap wrote a firewall projection without AirVPN metadata: %v", err)
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
	if !strings.Contains(string(data), "runtimeVariables[\"client_crl_bundle_pem\"] = clientCRL + rootCRL") {
		t.Fatal("Pulse nginx mTLS projection does not include the root CRL")
	}
	if !strings.Contains(string(data), "site.LoadRootCRL") || strings.Contains(string(data), "site.LoadAuthorityWithRootKey") {
		t.Fatal("deploy does not use a persisted public root CRL without decrypting the root key")
	}
}

func TestAIOpsCanaryUsesCompleteControllerCertificateChain(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "internal", "cli", "converge.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "tls.X509KeyPair([]byte(certificate.ChainPEM), []byte(certificate.KeyPEM))") {
		t.Fatal("AIOps canary does not send the complete controller certificate chain")
	}
}

func TestPulseCredentialBootstrapUsesTemporaryRootAuthority(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "internal", "cli", "converge.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `ReplacePulseMonitoringCredentials(ctx, rootRunner, s.BootstrapAddress, "root")`) {
		t.Fatal("Pulse Proxmox credential bootstrap does not use the temporary root authority")
	}
	if strings.Contains(text, `ReplacePulseMonitoringCredentials(context.Background(), proxmoxRunner, s.BootstrapAddress, model.DefaultAdminSSHUser)`) {
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

func TestDeploymentRootCleanupTracksAuthorityEstablishedDuringRearm(t *testing.T) {
	hostRunner := &deploymentRootTestRunner{hostOutput: []byte("{\"exitcode\":0,\"exited\":1,\"out-data\":\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\n\"}")}
	guestRunner := &deploymentRootTestRunner{guestErr: errors.New("permission denied"), guestSuccessAfter: 2}
	guest := proxmox.GuestPlan{VMID: model.ProxmoxVMID, Name: "lab-fw-01", Hostname: "lab-fw-01", Kind: proxmox.KindQEMU, Address: "10.10.99.1", Owner: "boetticher/core/firewall"}
	cleanup := newTemporaryRootCleanup(model.Site{}, t.TempDir(), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA operator")
	authorityEstablished := false
	if err := waitForDeploymentRoot(context.Background(), hostRunner, "192.0.2.10", guestRunner, guest, cleanup.operatorPublicKey, filepath.Join(t.TempDir(), "known_hosts"), "lab-fw-01.lab.home.arpa", func() {
		authorityEstablished = true
		cleanup.guestEstablished(guest)
	}); err != nil {
		t.Fatal(err)
	}
	if !authorityEstablished || len(cleanup.guests) != 1 {
		t.Fatalf("temporary root authority tracking = established:%t guests:%d", authorityEstablished, len(cleanup.guests))
	}
}

func TestTemporaryRootCleanupAttemptsEveryTargetAfterFailure(t *testing.T) {
	operatorKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA operator"
	guests := []proxmox.GuestPlan{
		{Name: "lab-dns-01", Address: "10.10.10.10", Owner: "boetticher/module/dns"},
		{Name: "lab-monitor-01", Address: "10.10.10.20", Owner: "boetticher/module/monitoring"},
	}
	var mu sync.Mutex
	seen := make(map[string]bool)
	sentinel := errors.New("guest unavailable")
	revoke := func(_ context.Context, _ proxmox.CommandRunner, address, _ string, _ string, host bool) error {
		mu.Lock()
		defer mu.Unlock()
		key := address
		if host {
			key = "host:" + address
		}
		seen[key] = true
		if address == "10.10.10.10" {
			return sentinel
		}
		return nil
	}
	err := revokeTemporaryRootAccessForGuestsWith(context.Background(), model.Site{BootstrapAddress: "192.0.2.10"}, t.TempDir(), guests, operatorKey, true, revoke)
	if !errors.Is(err, sentinel) {
		t.Fatalf("cleanup error = %v, want the failed guest error", err)
	}
	for _, key := range []string{"10.10.10.10", "10.10.10.20", "host:192.0.2.10"} {
		if !seen[key] {
			t.Fatalf("cleanup did not attempt %s; seen=%v", key, seen)
		}
	}
}

func TestTemporaryRootCleanupFallsBackThroughIndependentHost(t *testing.T) {
	operatorKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA operator"
	guests := []proxmox.GuestPlan{{VMID: 110, Name: "lab-dns-01", Kind: proxmox.KindLXC, Address: "10.10.10.10", Owner: "boetticher/module/dns"}}
	directCalls := 0
	hostFallbackCalls := 0
	hostCleanupCalls := 0
	direct := func(_ context.Context, _ proxmox.CommandRunner, address, _ string, _ string, host bool) error {
		if host {
			hostCleanupCalls++
			return nil
		}
		directCalls++
		return errors.New("guest SSH unavailable")
	}
	hostFallback := func(_ context.Context, _ proxmox.CommandRunner, address, _ string, kind proxmox.GuestKind, vmid int, _ string) error {
		if address != "192.0.2.10" || kind != proxmox.KindLXC || vmid != 110 {
			t.Fatalf("unexpected independent host fallback target: %s %s %d", address, kind, vmid)
		}
		hostFallbackCalls++
		return nil
	}
	if err := revokeTemporaryRootAccessForGuestsWithFallback(context.Background(), model.Site{BootstrapAddress: "192.0.2.10"}, t.TempDir(), guests, operatorKey, true, direct, hostFallback); err != nil {
		t.Fatal(err)
	}
	if directCalls != 1 || hostFallbackCalls != 1 || hostCleanupCalls != 1 {
		t.Fatalf("temporary root cleanup calls = direct:%d fallback:%d host:%d", directCalls, hostFallbackCalls, hostCleanupCalls)
	}
}

func TestTemporaryRootCleanupIgnoresAbsentPlannedGuest(t *testing.T) {
	operatorKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA operator"
	guests := []proxmox.GuestPlan{{VMID: 140, Name: "lab-log-01", Kind: proxmox.KindLXC, Address: "10.10.10.40", Owner: "boetticher/module/logging"}}
	direct := func(_ context.Context, _ proxmox.CommandRunner, _ string, _ string, _ string, host bool) error {
		if host {
			return nil
		}
		return errors.New("guest SSH unavailable")
	}
	hostFallback := func(_ context.Context, _ proxmox.CommandRunner, _ string, _ string, _ proxmox.GuestKind, _ int, _ string) error {
		return errors.New("Configuration file 'nodes/lab-proxmox-01/lxc/140.conf' does not exist")
	}
	if err := revokeTemporaryRootAccessForGuestsWithFallback(context.Background(), model.Site{BootstrapAddress: "192.0.2.10"}, t.TempDir(), guests, operatorKey, true, direct, hostFallback); err != nil {
		t.Fatalf("absent planned guest cleanup = %v", err)
	}
}

func TestRetainedGuestInactivationIgnoresAbsentGuest(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "internal", "cli", "converge.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "inactivate retained %s guest %s through Proxmox") || !strings.Contains(text, "configuration file") || !strings.Contains(text, "does not exist") {
		t.Fatal("retained guest inactivation does not handle an exact absent Proxmox guest")
	}
}

func TestInterruptedDeploymentCleanupUsesPersistedTargets(t *testing.T) {
	dir := t.TempDir()
	publicKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA boetticher-apply"
	state := site.OperationState{
		ID: "run-1", Kind: "deploy", Phase: site.PhaseVerify, ModelRevision: "model-1", PlanDigest: strings.Repeat("a", 64),
		TemporaryPublicKey:     publicKey,
		TemporaryHostAddress:   "192.0.2.10",
		TemporaryCleanupGuests: []site.OperationGuest{{Name: "lab-fw-01", Kind: "qemu", VMID: 100, Address: "10.10.99.1"}},
	}
	if err := site.SaveOperationState(dir, state); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := recoverInterruptedDeploymentWith(context.Background(), dir, model.Site{BootstrapAddress: "192.0.2.10"}, io.Discard, func(_ context.Context, siteDir string, cleanupSite model.Site, guests []proxmox.GuestPlan, gotKey string) error {
		called = true
		if siteDir != dir || cleanupSite.BootstrapAddress != "192.0.2.10" || gotKey != publicKey || len(guests) != 1 || guests[0].Name != "lab-fw-01" || guests[0].Kind != proxmox.KindQEMU || guests[0].VMID != 100 || guests[0].Address != "10.10.99.1" {
			t.Fatalf("unexpected interrupted cleanup: dir=%s site=%#v guests=%#v key=%q", siteDir, cleanupSite, guests, gotKey)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("interrupted deployment cleanup was not invoked")
	}
	if _, found, err := site.LoadOperationState(dir); err != nil || found {
		t.Fatalf("successful interrupted cleanup left operation state: err=%v found=%t", err, found)
	}
}

func TestInterruptedDeploymentCleanupFailureLeavesFailedJournal(t *testing.T) {
	dir := t.TempDir()
	publicKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA boetticher-apply"
	if err := site.SaveOperationState(dir, site.OperationState{
		ID: "run-1", Kind: "deploy", Phase: site.PhaseApply, ModelRevision: "model-1", PlanDigest: strings.Repeat("a", 64), TemporaryPublicKey: publicKey, TemporaryHostAddress: "192.0.2.10",
	}); err != nil {
		t.Fatal(err)
	}
	cleanupErr := errors.New("independent host unavailable")
	err := recoverInterruptedDeploymentWith(context.Background(), dir, model.Site{BootstrapAddress: "192.0.2.10"}, io.Discard, func(context.Context, string, model.Site, []proxmox.GuestPlan, string) error {
		return cleanupErr
	})
	if err == nil || !strings.Contains(err.Error(), "HOLD: interrupted deployment cleanup failed") {
		t.Fatalf("cleanup failure did not produce a HOLD: %v", err)
	}
	state, found, loadErr := site.LoadOperationState(dir)
	if loadErr != nil || !found || state.Phase != site.PhaseFailed || state.TemporaryPublicKey != publicKey {
		t.Fatalf("failed cleanup journal = %#v, found=%t, err=%v", state, found, loadErr)
	}
}

func TestInterruptedDeploymentCleanupRejectsHostAddressDrift(t *testing.T) {
	dir := t.TempDir()
	publicKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA boetticher-apply"
	if err := site.SaveOperationState(dir, site.OperationState{
		ID: "run-1", Kind: "deploy", Phase: site.PhaseApply, ModelRevision: "model-1", PlanDigest: strings.Repeat("a", 64), TemporaryPublicKey: publicKey, TemporaryHostAddress: "192.0.2.11",
	}); err != nil {
		t.Fatal(err)
	}
	called := false
	err := recoverInterruptedDeploymentWith(context.Background(), dir, model.Site{BootstrapAddress: "192.0.2.10"}, io.Discard, func(context.Context, string, model.Site, []proxmox.GuestPlan, string) error {
		called = true
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "host address changed") {
		t.Fatalf("host address drift was accepted: %v", err)
	}
	if called {
		t.Fatal("host address drift attempted cleanup")
	}
}

func TestInterruptedPreApplyJournalIsClearedWithoutCleanup(t *testing.T) {
	dir := t.TempDir()
	if err := site.SaveOperationState(dir, site.OperationState{ID: "run-1", Kind: "deploy", Phase: site.PhasePlan, ModelRevision: "model-1"}); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := recoverInterruptedDeploymentWith(context.Background(), dir, model.Site{}, io.Discard, func(context.Context, string, model.Site, []proxmox.GuestPlan, string) error {
		called = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("pre-Apply journal attempted temporary-authority cleanup")
	}
	if _, found, err := site.LoadOperationState(dir); err != nil || found {
		t.Fatalf("pre-Apply journal was not cleared: err=%v found=%t", err, found)
	}
}

func TestInterruptedPreApplyFailureJournalIsClearedWithoutCleanup(t *testing.T) {
	dir := t.TempDir()
	if err := site.SaveOperationState(dir, site.OperationState{ID: "run-1", Kind: "deploy", Phase: site.PhaseFailed, ModelRevision: "model-1", Error: "live plan was stale"}); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := recoverInterruptedDeploymentWith(context.Background(), dir, model.Site{}, io.Discard, func(context.Context, string, model.Site, []proxmox.GuestPlan, string) error {
		called = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("pre-Apply failure journal attempted temporary-authority cleanup")
	}
	if _, found, err := site.LoadOperationState(dir); err != nil || found {
		t.Fatalf("pre-Apply failure journal was not cleared: err=%v found=%t", err, found)
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
	if !strings.Contains(text, `bastionRunner.StartLocalForward(ctx, s.BootstrapAddress, "lab-jump", "10.10.20.60", 443)`) {
		t.Fatal("AIOps canary does not use the restricted bastion tunnel to the internal AI Router")
	}
	if strings.Contains(text, `StartLocalForward(ctx, s.BootstrapAddress, "root", "10.10.20.60", 443)`) {
		t.Fatal("AIOps canary still uses the deployment-only root forwarding path")
	}
}

func TestAIOpsModelCapabilitiesUseTheBifrostAlias(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "internal", "cli", "converge.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `"/usr/local/libexec/boetticher-bifrost-model-capabilities", modelConfig.Alias`) {
		t.Fatal("AIOps model capability lookup does not use the declared Bifrost alias")
	}
	if strings.Contains(text, `"/usr/local/libexec/boetticher-bifrost-model-capabilities", modelConfig.Model`) {
		t.Fatal("AIOps model capability lookup passes the provider model instead of the Bifrost alias")
	}
}

func TestDeployReconcilesLiveBastionPolicyFromCanonicalDestinations(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "internal", "cli", "converge.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, required := range []string{
		`proxmox.ConfigureBastionPolicy(ctx, rootRunner, s.BootstrapAddress, "root", jumpDestinations(s))`,
		`Reconcile the live host-side jump policy`,
		`proxmox.InactivateRetainedModule(ctx, rootRunner, s.BootstrapAddress, "root", guest.Kind, guest.VMID, module)`,
		`context.WithTimeout(ctx, deploymentRootTimeout)`,
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("deploy does not reconcile the live bastion policy: missing %q", required)
		}
	}
}

func TestDeployAcquiresTemporaryRootOnlyAfterExactPlanAcceptance(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "internal", "cli", "converge.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	digest := strings.Index(text, "planDigest, err := digestDeploymentPlan")
	accept := strings.Index(text, "if *planDigestFlag != \"\" && *planDigestFlag != planDigest")
	register := strings.Index(text, "registerCleanup(func(cleanupCtx context.Context) error")
	acquire := strings.Index(text, "proxmox.InstallTemporaryRootAccess(ctx, recoveryRunner")
	bind := strings.Index(text, "proxmoxClient.SetSnippetRunner(rootRunner")
	if digest < 0 || accept < digest || register < accept || acquire < register || bind < acquire {
		t.Fatalf("temporary Apply authority sequencing is not digest-gated: digest=%d accept=%d register=%d acquire=%d bind=%d", digest, accept, register, acquire, bind)
	}
	if strings.Contains(text[:accept], "WaitForSSH(ctx, rootRunner") || strings.Contains(text[:accept], "ConfigureIdentities(ctx, rootRunner") {
		t.Fatal("deployment uses deployment root authority before exact plan acceptance")
	}
	if !strings.Contains(text[acquire:], "temporaryPrivateKey") {
		t.Fatal("temporary Apply identity is not retained for the bounded Apply lifecycle")
	}
	for _, required := range []string{
		`proxmox.EnsureScopedCredentialACL(ctx, rootRunner, s.BootstrapAddress, "root", "labadmin@pve", "boetticher", "BoetticherProvisioner", node)`,
		"proxmoxPlan.OperatorPublicKey = durableOperatorPublicKey",
		"RenderFirewallCloudInitWithKey(guest, durableOperatorPublicKey)",
		"firewallGuest, deploymentPublicKey",
		"guest, deploymentPublicKey",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("deployment does not separate durable and temporary identities: missing %q", required)
		}
	}
	journalKey := strings.Index(text, "operationState.TemporaryPublicKey = deploymentPublicKey")
	journalGuests := strings.Index(text, "operationState.TemporaryCleanupGuests = cleanupGuests")
	journalSave := -1
	if journalGuests >= 0 {
		journalSaveOffset := strings.Index(text[journalGuests:], "site.SaveOperationState(*siteDir, operationState)")
		if journalSaveOffset >= 0 {
			journalSave = journalGuests + journalSaveOffset
		}
	}
	if journalKey < accept || journalGuests < journalKey || journalSave < journalGuests || journalSave > acquire {
		t.Fatalf("temporary Apply authority was not journaled before installation: key=%d guests=%d save=%d acquire=%d", journalKey, journalGuests, journalSave, acquire)
	}
	guestRegistration := strings.Index(text, "rootCleanup.guestEstablished(firewallGuest)")
	guestReadiness := strings.Index(text, "return waitForDeploymentRoot(ctx, rootRunner, s.BootstrapAddress, firewallRunner.FreshConnection()")
	if guestRegistration < 0 || guestReadiness < 0 || guestRegistration > guestReadiness {
		t.Fatal("managed gateway was not registered for cleanup before its temporary-root readiness probe")
	}
}

func TestTemporaryRootIdentityIsInMemoryAndScoped(t *testing.T) {
	privateKey, publicKey, err := newTemporaryRootIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(privateKey), "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Fatal("temporary identity is not an OpenSSH private key")
	}
	if !strings.HasSuffix(publicKey, " boetticher-apply") {
		t.Fatalf("temporary identity is not explicitly scoped: %q", publicKey)
	}
	if err := proxmox.ValidatePublicKey(publicKey); err != nil {
		t.Fatalf("temporary public identity is invalid: %v", err)
	}
	for index := range privateKey {
		privateKey[index] = 0
	}
}

func TestOperatorPublicKeyForSiteUsesDurablePublicIdentity(t *testing.T) {
	dir := t.TempDir()
	identity := filepath.Join(dir, "id_ed25519")
	publicKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBoetticherTrial operator"
	if err := os.WriteFile(identity+".pub", []byte(publicKey+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s := model.NewDefaultSite("installation", "age1example")
	s.SSHIdentityFile = identity
	got, err := operatorPublicKeyForSite(s)
	if err != nil {
		t.Fatal(err)
	}
	if got != publicKey {
		t.Fatalf("durable operator public key = %q, want %q", got, publicKey)
	}
}

func TestDeploymentLockInputsRecognizeSiteAndDryRunFlags(t *testing.T) {
	if siteDir, dryRun := deploymentLockInputs([]string{"--site", "/tmp/site", "--dry-run"}); siteDir != "/tmp/site" || !dryRun {
		t.Fatalf("deployment lock inputs = %q, %t", siteDir, dryRun)
	}
	if siteDir, dryRun := deploymentLockInputs([]string{"--site=/tmp/site"}); siteDir != "/tmp/site" || dryRun {
		t.Fatalf("deployment lock inputs = %q, %t", siteDir, dryRun)
	}
}

func TestLiveDeploymentObservesManagedFirewallAndModuleGuests(t *testing.T) {
	s := model.NewDefaultSite("deployment-observations", "age1observations")
	composed, _, err := modules.Compose(model.ConfigFromSite(s))
	if err != nil {
		t.Fatal(err)
	}
	s = composed
	plan, err := proxmox.PlanFromSite(s)
	if err != nil {
		t.Fatal(err)
	}
	guests := deploymentGuestPlans(s, plan)
	if len(guests) != 3 {
		t.Fatalf("live deployment observed %d guests, want the firewall and two default module guests: %#v", len(guests), guests)
	}
	foundFirewall := false
	for _, guest := range guests {
		if guest.Name == "lab-fw-01" && guest.Kind == proxmox.KindQEMU {
			foundFirewall = true
		}
	}
	if !foundFirewall {
		t.Fatalf("live deployment observations omitted the managed firewall QEMU: %#v", guests)
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
		`pki.IssueClient(authority, "operator"`,
		"pulse.NewReadClient(pulse.ClientConfig{",
		"CAPEM:",
		"pulseRead.StateSummary(ctx)",
		"pulse.IsUnauthorized(err)",
		"pulseAdmin.CreateReadToken(ctx, \"boetticher monitoring read\")",
		"site.StorePlatformSecret(*siteDir, s, *ageIdentity, \"pulse_api_token\", readToken)",
		"verify Pulse state summary after read-token refresh",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("Pulse read-token recovery is missing %q", required)
		}
	}
	if !strings.Contains(text, "ClientCertPEM: pulseOperatorCertificate.ChainPEM") || !strings.Contains(text, "ClientKeyPEM: pulseOperatorCertificate.KeyPEM") {
		t.Fatal("Pulse admin client does not use the operator mTLS certificate")
	}
	if strings.Contains(text, "pulseAdmin.ValidateReadToken(ctx, readToken)") {
		t.Fatal("AIOps Pulse token validation must use the dedicated read client")
	}
	if strings.Contains(text, `pki.IssueClient(authority, "boetticher-pulse-read"`) {
		t.Fatal("Pulse read clients must use scoped API tokens without client certificates")
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
	got := deploymentModuleNames(resolved, "")
	want := []string{"dns", "monitoring"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("external deployment order = %v, want %v", got, want)
	}
}

func TestArtifactQualificationStatusDistinguishesDefinitionAndContent(t *testing.T) {
	artifact := model.Artifact{Name: "boetticher-dns-blocky"}
	if got := artifactQualificationStatus(artifact); got != "FAIL (qualified content evidence absent)" {
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
	if err := runDeploy([]string{"--site", siteDir, "--dry-run", "--replace-firewall"}, &output); err == nil {
		t.Fatal("dry-run unexpectedly passed without qualified artifacts")
	}
	if !strings.Contains(output.String(), "Artifact qualification: FAIL") {
		t.Fatalf("dry-run omitted failed qualification: %s", output.String())
	}
	if !strings.Contains(output.String(), "Deployment: FAIL") || !strings.Contains(output.String(), "Infrastructure changed: NO") {
		t.Fatalf("dry-run omitted binary deployment summary: %s", output.String())
	}
	if !strings.Contains(output.String(), "Firewall root recovery: requested (dry-run; declared persistent volumes remain attached)") {
		t.Fatalf("dry-run omitted requested firewall recovery: %s", output.String())
	}
	if _, err := os.Stat(filepath.Join(siteDir, "generated", "model.json")); !os.IsNotExist(err) {
		t.Fatalf("deploy dry-run wrote a local model projection: %v", err)
	}
}

func TestValidateDeployRecoveryOptions(t *testing.T) {
	tests := []struct {
		name               string
		mode               string
		replaceFirewall    bool
		recreateLegacyLXCs bool
		confirm            bool
		dryRun             bool
		want               string
	}{
		{name: "ordinary deployment", mode: model.GatewayModeManaged},
		{name: "managed dry run", mode: model.GatewayModeManaged, replaceFirewall: true, dryRun: true},
		{name: "managed confirmed", mode: model.GatewayModeManaged, replaceFirewall: true, confirm: true},
		{name: "managed unconfirmed", mode: model.GatewayModeManaged, replaceFirewall: true, want: "requires --confirm"},
		{name: "external gateway", mode: model.GatewayModeExternal, replaceFirewall: true, confirm: true, want: "managed gateway mode"},
		{name: "legacy LXC dry run", mode: model.GatewayModeManaged, recreateLegacyLXCs: true, dryRun: true},
		{name: "legacy LXC confirmed", mode: model.GatewayModeManaged, recreateLegacyLXCs: true, confirm: true},
		{name: "legacy LXC unconfirmed", mode: model.GatewayModeManaged, recreateLegacyLXCs: true, want: "--recreate-legacy-lxcs requires --confirm"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateDeployRecoveryOptions(test.mode, test.replaceFirewall, test.recreateLegacyLXCs, test.confirm, test.dryRun)
			if test.want == "" && err != nil {
				t.Fatalf("validateDeployRecoveryOptions() = %v", err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("validateDeployRecoveryOptions() = %v, want %q", err, test.want)
			}
		})
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

func TestPlanDigestFromOutputRequiresCanonicalSHA256Digest(t *testing.T) {
	want := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	got, err := planDigestFromOutput("Deployment plan: PASS\n  Digest: " + want + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("digest = %q, want %q", got, want)
	}
	for _, output := range []string{
		"Deployment plan: PASS\n",
		"  Digest: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg\n",
		"  Digest: sha256:0123456789abcdef\n",
	} {
		if _, err := planDigestFromOutput(output); err == nil {
			t.Fatalf("plan digest parser accepted invalid output %q", output)
		}
	}
}

func TestScopedModuleDeployDoesNotCallGlobalMutationBoundaries(t *testing.T) {
	data, err := os.ReadFile("converge.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	start := strings.Index(text, "func runScopedModuleDeploy(")
	end := strings.Index(text[start:], "\nfunc waitForDeploymentRoot(")
	if start < 0 || end < 0 {
		t.Fatal("scoped deployment implementation is missing")
	}
	scoped := text[start : start+end]
	for _, forbidden := range []string{
		"ConfigureBastionPolicy", "ConfigureIdentities", "EnsureLVMThinStorageWithMutation",
		"EnsureDirectoryStorageContentWithMutation", "EnsureFirewallVM", "ApplyBackupJobWithRunner",
		"writeModelProjections", "ConfigureProxmox", "StorePlatformSecret", "PurgeModule",
	} {
		if strings.Contains(scoped, forbidden) {
			t.Fatalf("scoped deployment still reaches global mutation %s", forbidden)
		}
	}
	for _, required := range []string{"ProvisionModule", "installModuleRuntimeConfigs", "runTrackedAnsible", "SaveOperationState", "ClearOperationState"} {
		if !strings.Contains(scoped, required) {
			t.Fatalf("scoped deployment omitted required target lifecycle action %s", required)
		}
	}
	if !strings.Contains(scoped, "plan.OperatorPublicKey = durableOperatorPublicKey") || strings.Contains(scoped, "plan.OperatorPublicKey = publicKey") {
		t.Fatal("scoped deployment can install its temporary key as durable labadmin access")
	}
	entry := strings.Index(text, "if *onlyModule != \"\" {")
	if entry < 0 || !strings.Contains(text[entry:start], "recoverInterruptedDeployment") {
		t.Fatal("scoped deployment can overwrite an interrupted deployment journal before recovery")
	}
}
