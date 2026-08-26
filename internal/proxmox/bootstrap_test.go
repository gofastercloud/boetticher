package proxmox

import (
	"context"
	"strings"
	"testing"
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

func (f *fakeRunner) Run(_ context.Context, address, user, command string) ([]byte, error) {
	f.address, f.user, f.command = address, user, command
	f.commands = append(f.commands, command)
	if command == "ip -j route show default" && f.routeOutput != nil {
		return f.routeOutput, nil
	}
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
