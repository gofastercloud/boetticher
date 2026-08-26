package proxmox

import (
	"context"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	address     string
	user        string
	command     string
	commands    []string
	output      []byte
	routeOutput []byte
}

func TestManagementNetworkConfigIsFixedAndPreservesHOME(t *testing.T) {
	if !strings.Contains(managementInterfaceConfig, "vmbr1.99") || !strings.Contains(managementInterfaceConfig, "10.10.99.5/24") || !strings.Contains(managementInterfaceConfig, "10.10.0.0/16 via 10.10.99.1") {
		t.Fatal("management interface configuration is incomplete")
	}
	if strings.Contains(managementInterfaceConfig, "gateway") || strings.Contains(managementInterfaceConfig, "vmbr0") {
		t.Fatal("management interface configuration changes the HOME/default route")
	}
}

func TestWaitForSSHRejectsInvalidIdentityBeforeNetworkAccess(t *testing.T) {
	if err := WaitForSSH(context.Background(), &fakeRunner{}, "not-an-ip", "labadmin", 1, 0); err == nil || !strings.Contains(err.Error(), "identity is invalid") {
		t.Fatalf("invalid SSH identity was not rejected: %v", err)
	}
}

func TestWaitForSSHUsesConfiguredRunnerForBastionTransport(t *testing.T) {
	runner := &fakeRunner{}
	if err := WaitForSSH(context.Background(), runner, "192.0.2.10", "labadmin", 1, time.Millisecond); err != nil {
		t.Fatalf("WaitForSSH() = %v", err)
	}
	if runner.command != "true" {
		t.Fatalf("readiness did not execute the authenticated probe: %q", runner.command)
	}
}

func TestWaitForCommandUsesAuthenticatedReadinessProbe(t *testing.T) {
	runner := &fakeRunner{}
	if err := WaitForCommand(context.Background(), runner, "192.0.2.10", "labadmin", "test -f /run/ready", 1, time.Millisecond); err != nil {
		t.Fatalf("WaitForCommand() = %v", err)
	}
	if runner.command != "test -f /run/ready" {
		t.Fatalf("command readiness probe = %q", runner.command)
	}
}

func TestSSHRunnerPreservesJournalArgumentsWithoutShellInterpolation(t *testing.T) {
	runner := SSHRunner{ConfigFile: "/tmp/boetticher.conf", StrictHostKey: "ask"}
	args, err := runner.commandArgs("192.0.2.10", "labadmin", []string{
		"journalctl", "--no-pager", "--lines=25", "--directory=/var/log/journal/remote",
		"_HOSTNAME=lab-dns-01", "_SYSTEMD_UNIT=blocky.service", "--since=2026-08-27T00:00:00Z", "-p", "warning",
	})
	if err != nil {
		t.Fatal(err)
	}
	wantSuffix := []string{
		"labadmin@192.0.2.10", "journalctl", "--no-pager", "--lines=25",
		"--directory=/var/log/journal/remote", "_HOSTNAME=lab-dns-01",
		"_SYSTEMD_UNIT=blocky.service", "--since=2026-08-27T00:00:00Z", "-p", "warning",
	}
	if len(args) < len(wantSuffix) || !reflect.DeepEqual(args[len(args)-len(wantSuffix):], wantSuffix) {
		t.Fatalf("SSH invocation did not preserve argument boundaries: %#v", args)
	}
	for _, arg := range args {
		if strings.Contains(arg, "'\\''") || strings.Contains(arg, "journalctl ") {
			t.Fatalf("SSH invocation contains shell-assembled input: %#v", args)
		}
	}
}

func TestSSHRunnerUsesBoundedTOFUForFreshApplianceHostKeys(t *testing.T) {
	runner := SSHRunner{StrictHostKey: "accept-new", HostAlias: "lab-dns-01"}
	args, err := runner.commandArgs("10.10.20.10", "labadmin", []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "StrictHostKeyChecking=accept-new") {
		t.Fatalf("fresh appliance probe does not enroll a new host key safely: %#v", args)
	}
	if strings.Contains(joined, "StrictHostKeyChecking=no") {
		t.Fatalf("fresh appliance probe disables host-key verification: %#v", args)
	}
}

func TestConfigureManagementNetworkValidatesUnchangedHOMEAndVLANState(t *testing.T) {
	runner := &fakeRunner{}
	if err := ConfigureManagementNetwork(context.Background(), runner, "192.0.2.10", "labadmin"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(runner.command, "before_vmbr0_addr") || !strings.Contains(runner.command, "before_default_route") {
		t.Fatalf("management verification does not preserve HOME state: %s", runner.command)
	}
	for _, required := range []string{"10.10.99.5/24", "10.10.0.0/16 via 10.10.99.1 dev vmbr1.99", "vlan_filtering"} {
		if !strings.Contains(runner.command, required) {
			t.Fatalf("management verification missing %q: %s", required, runner.command)
		}
	}
}

func (f *fakeRunner) Run(_ context.Context, address, user, command string) ([]byte, error) {
	f.address, f.user, f.command = address, user, command
	f.commands = append(f.commands, command)
	if command == "ip -j route show default" && f.routeOutput != nil {
		return f.routeOutput, nil
	}
	return f.output, nil
}

func (f *fakeRunner) RunWithStdin(_ context.Context, address, user, command string, _ io.Reader) ([]byte, error) {
	f.address, f.user, f.command = address, user, command
	f.commands = append(f.commands, command)
	return f.output, nil
}

func TestInstallOperatorKeyUsesSafeConstantRemoteCommand(t *testing.T) {
	runner := &fakeRunner{}
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample operator"
	if err := InstallOperatorKey(context.Background(), runner, "192.0.2.10", "root", key); err != nil {
		t.Fatal(err)
	}
	if runner.address != "192.0.2.10" || runner.user != "root" || !strings.Contains(runner.command, "authorized_keys") {
		t.Fatalf("unexpected bootstrap request: %#v", runner)
	}
	if strings.Contains(runner.command, "StrictHostKeyChecking=no") || strings.Contains(runner.command, "password") {
		t.Fatalf("bootstrap command weakened SSH or accepted a password argument: %s", runner.command)
	}
}

func TestCreateScopedCredentialsCapturesOnlyReturnedSecret(t *testing.T) {
	runner := &fakeRunner{output: []byte(`{"value":"opaque-token-secret"}`)}
	secret, err := CreateScopedCredentials(context.Background(), runner, "192.0.2.10", "root", "labadmin@pve", "boetticher")
	if err != nil || secret != "opaque-token-secret" {
		t.Fatalf("CreateScopedCredentials() = %q, %v", secret, err)
	}
	if strings.Contains(runner.command, "opaque-token-secret") {
		t.Fatal("returned token secret was interpolated into the remote command")
	}
	if strings.Contains(runner.command, "|| true") {
		t.Fatal("credential bootstrap must not mask identity or privilege errors")
	}
}

func TestDiscoverPhysicalNetworkViaSSHUsesReadOnlyPveshEvidence(t *testing.T) {
	runner := &fakeRunner{output: []byte(`[
  {"iface":"vmbr0","type":"bridge","address":"192.0.2.73/24","gateway":"192.0.2.1","bridge_ports":"eno1"},
  {"iface":"vmbr1","type":"bridge","bridge_ports":"none","bridge_vlan_aware":true},
  {"iface":"eno1","type":"eth","hwaddr":"00:11:22:33:44:55","active":true},
  {"iface":"enp5s0","type":"eth","hwaddr":"00:aa:bb:cc:dd:ee","active":false}
	]`), routeOutput: []byte(`[{"dev":"vmbr0"}]`)}
	discovery, err := DiscoverPhysicalNetworkViaSSH(context.Background(), runner, "192.0.2.73", "root", "lab-proxmox-01", "192.0.2.73", "", "")
	if err != nil || discovery.Mode != "physical-trunk" || discovery.Trunk == nil || discovery.Trunk.Name != "enp5s0" {
		t.Fatalf("unexpected SSH discovery: %#v, %v", discovery, err)
	}
	if len(runner.commands) != 2 || runner.commands[0] != "pvesh get /nodes/lab-proxmox-01/network --output-format json" || runner.commands[1] != "ip -j route show default" {
		t.Fatalf("unexpected discovery commands: %#v", runner.commands)
	}
}
