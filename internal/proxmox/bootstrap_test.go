package proxmox

import (
	"context"
	"errors"
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
	responses   map[string][]byte
	errors      map[string]error
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

func TestSSHRunnerSeparatesHostKeyAliasFromNetworkTarget(t *testing.T) {
	runner := SSHRunner{StrictHostKey: "accept-new", HostKeyAlias: "lab-proxmox-01"}
	args, err := runner.commandArgs("192.0.4.5", "dave", []string{"pvesh", "get", "/nodes"})
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(args, "HostKeyAlias=lab-proxmox-01") {
		t.Fatalf("bootstrap host-key alias missing: %#v", args)
	}
	if !containsString(args, "dave@192.0.4.5") {
		t.Fatalf("bootstrap target changed from the address: %#v", args)
	}
	if containsString(args, "dave@lab-proxmox-01") {
		t.Fatalf("bootstrap used the logical identity as a network target: %#v", args)
	}
}

func TestSSHRunnerHostAliasStillSelectsApplianceConfigHost(t *testing.T) {
	runner := SSHRunner{HostAlias: "lab-dns-01", HostKeyAlias: "lab-proxmox-01"}
	args, err := runner.commandArgs("10.10.20.10", "labadmin", []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(args, "labadmin@lab-dns-01") || !containsString(args, "HostKeyAlias=lab-proxmox-01") {
		t.Fatalf("appliance HostAlias and independent HostKeyAlias were not preserved: %#v", args)
	}
}

func TestConfigureManagementNetworkValidatesUnchangedHOMEAndVLANState(t *testing.T) {
	runner := &fakeRunner{responses: map[string][]byte{
		"sudo -n /usr/sbin/ip -4 -j addr show dev vmbr0":  []byte(`[{"addr":"192.0.2.10/24"}]`),
		"sudo -n /usr/sbin/ip -4 -j route show default":   []byte(`[{"dst":"default","gateway":"192.0.2.1"}]`),
		"sudo -n /usr/sbin/ip -4 addr show dev vmbr1.99":  []byte("inet 10.10.99.5/24"),
		"sudo -n /usr/sbin/ip -4 route show 10.10.0.0/16": []byte("10.10.0.0/16 via 10.10.99.1 dev vmbr1.99"),
		"sudo -n /usr/sbin/ip -d link show dev vmbr1":     []byte("vlan_filtering 1"),
	}}
	if err := ConfigureManagementNetwork(context.Background(), runner, "192.0.2.10", "labadmin"); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"sudo -n /usr/sbin/ip -4 -j addr show dev vmbr0",
		"sudo -n /usr/sbin/ip -4 -j route show default",
		"sudo -n /usr/sbin/ifreload -a",
		"sudo -n /usr/sbin/ip -4 addr show dev vmbr1.99",
		"sudo -n /usr/sbin/ip -4 route show 10.10.0.0/16",
		"sudo -n /usr/sbin/ip -d link show dev vmbr1",
	} {
		if !containsString(runner.commands, required) {
			t.Fatalf("management verification missing fixed command %q: %#v", required, runner.commands)
		}
	}
	if containsString(runner.commands, "sudo -n sh -c") {
		t.Fatalf("management verification uses an unbounded shell: %#v", runner.commands)
	}
}

func (f *fakeRunner) Run(_ context.Context, address, user, command string) ([]byte, error) {
	f.address, f.user, f.command = address, user, command
	f.commands = append(f.commands, command)
	if err, ok := f.errors[command]; ok {
		return nil, err
	}
	if response, ok := f.responses[command]; ok {
		return response, nil
	}
	if command == "ip -j route show default" && f.routeOutput != nil {
		return f.routeOutput, nil
	}
	return f.output, nil
}

func TestWaitForQEMUIPv4ViaNeighborMatchesOnlyBuilderMAC(t *testing.T) {
	runner := &fakeRunner{responses: map[string][]byte{
		"/usr/sbin/ip -4 neigh show dev vmbr0": []byte("192.168.4.50 lladdr aa:bb:cc:dd:ee:ff STALE\n192.168.4.51 lladdr 02:00:00:00:01:90 REACHABLE\n"),
	}}
	address, err := WaitForQEMUIPv4ViaNeighbor(context.Background(), runner, "192.168.4.5", "root", "02:00:00:00:01:90", 1, time.Millisecond)
	if err != nil || address != "192.168.4.51" {
		t.Fatalf("WaitForQEMUIPv4ViaNeighbor() = %q, %v", address, err)
	}
}

func TestWaitForQEMUIPv4ViaNeighborRejectsMissingBuilderMAC(t *testing.T) {
	runner := &fakeRunner{responses: map[string][]byte{
		"/usr/sbin/ip -4 neigh show dev vmbr0": []byte("192.168.4.50 lladdr aa:bb:cc:dd:ee:ff STALE\n"),
	}}
	if address, err := WaitForQEMUIPv4ViaNeighbor(context.Background(), runner, "192.168.4.5", "root", "02:00:00:00:01:90", 1, time.Millisecond); err == nil || address != "" || !strings.Contains(err.Error(), "HOLD") {
		t.Fatalf("WaitForQEMUIPv4ViaNeighbor() = %q, %v", address, err)
	}
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
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
	runner := &fakeRunner{
		output: []byte(`{"value":"opaque-token-secret"}`),
		responses: map[string][]byte{
			"pvesh get /access/roles --output-format json":                      []byte(`[]`),
			"pvesh get /access/users --output-format json":                      []byte(`[]`),
			"pvesh get /access/users/'labadmin@pve'/token --output-format json": []byte(`[]`),
		},
	}
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

func TestCreateScopedCredentialsCreatesRoleAtCollectionEndpoint(t *testing.T) {
	runner := &fakeRunner{
		output: []byte(`{"value":"opaque-token-secret"}`),
		responses: map[string][]byte{
			"pvesh get /access/roles --output-format json":                      []byte(`[]`),
			"pvesh get /access/users --output-format json":                      []byte(`[]`),
			"pvesh get /access/users/'labadmin@pve'/token --output-format json": []byte(`[]`),
		},
	}
	if _, err := CreateScopedCredentialsWithRole(context.Background(), runner, "192.0.2.10", "root", "labadmin@pve", "boetticher", "BoetticherProvisioner"); err != nil {
		t.Fatal(err)
	}
	for _, command := range runner.commands {
		if strings.Contains(command, "pvesh create /access/roles") {
			if !strings.Contains(command, "pvesh create /access/roles --roleid 'BoetticherProvisioner'") {
				t.Fatalf("role creation used the wrong Proxmox API shape: %s", command)
			}
		}
		if strings.Contains(command, "pvesh set /access/acl") && strings.Contains(command, "--tokens 'labadmin@pve!boetticher'") && !strings.Contains(command, "--users") {
			return
		}
	}
	t.Fatal("credential bootstrap did not update ACL through the Proxmox set endpoint")
}

func TestCreateScopedCredentialsStopsOnUserLookupFailure(t *testing.T) {
	runner := &credentialLookupRunner{responses: map[string]error{
		"pvesh get /access/users --output-format json": errors.New("permission denied"),
	}}
	_, err := CreateScopedCredentialsWithRole(context.Background(), runner, "192.0.2.10", "root", "labadmin@pve", "boetticher", "BoetticherProvisioner")
	if err == nil || !strings.Contains(err.Error(), "HOLD: inspect Proxmox users") {
		t.Fatalf("user lookup failure was not held: %v", err)
	}
	for _, command := range runner.commands {
		if strings.Contains(command, "create /access/users") {
			t.Fatalf("user lookup failure triggered creation: %s", command)
		}
	}
}

type credentialLookupRunner struct {
	responses map[string]error
	commands  []string
}

func (r *credentialLookupRunner) Run(_ context.Context, _ string, _ string, command string) ([]byte, error) {
	r.commands = append(r.commands, command)
	if err, ok := r.responses[command]; ok {
		return nil, err
	}
	if strings.Contains(command, "/access/roles") {
		return []byte(`[]`), nil
	}
	return []byte(`[]`), nil
}

func TestScopedProvisionerPrivilegesAreExplicitAndBounded(t *testing.T) {
	want := "VM.Allocate VM.Audit VM.Config.CDROM VM.Config.CPU VM.Config.Cloudinit VM.Config.Disk VM.Config.HWType VM.Config.Memory VM.Config.Network VM.Config.Options VM.GuestAgent.Audit VM.PowerMgmt Datastore.Allocate Datastore.AllocateSpace Datastore.AllocateTemplate Datastore.Audit SDN.Audit SDN.Use Sys.AccessNetwork Sys.Audit Sys.Modify"
	if got := ScopedProvisionerPrivileges(); got != want {
		t.Fatalf("ScopedProvisionerPrivileges() = %q, want %q", got, want)
	}
	if strings.Contains(strings.ToLower(ScopedProvisionerPrivileges()), "administrator") || strings.Contains(strings.ToLower(ScopedProvisionerPrivileges()), "root") {
		t.Fatal("scoped provisioner role contains an administrator-equivalent privilege")
	}
}

func TestValidateScopedRoleJSONRequiresExactPrivileges(t *testing.T) {
	wanted := ScopedProvisionerPrivileges()
	roleJSON := `{"data":[{"roleid":"BoetticherProvisioner","privs":"Sys.Audit,VM.PowerMgmt,VM.Allocate,VM.Audit,VM.Config.CDROM,VM.Config.CPU,VM.Config.Cloudinit,VM.Config.Disk,VM.Config.HWType,VM.Config.Memory,VM.Config.Network,VM.Config.Options,VM.GuestAgent.Audit,Datastore.Allocate,Datastore.AllocateSpace,Datastore.AllocateTemplate,Datastore.Audit,SDN.Audit,SDN.Use,Sys.AccessNetwork,Sys.Modify","special":0}]}`
	exists, err := validateScopedRoleJSON([]byte(roleJSON), "BoetticherProvisioner", wanted)
	if err != nil || !exists {
		t.Fatalf("equivalent privilege set was rejected: exists=%t err=%v", exists, err)
	}

	missing, err := validateScopedRoleJSON([]byte(`[]`), "BoetticherProvisioner", wanted)
	if err != nil || missing {
		t.Fatalf("absent role was not distinguishable: exists=%t err=%v", missing, err)
	}

	_, err = validateScopedRoleJSON([]byte(`[{"roleid":"BoetticherProvisioner","privs":"VM.Audit","special":0}]`), "BoetticherProvisioner", wanted)
	if err == nil || !strings.Contains(err.Error(), "do not match required set") {
		t.Fatalf("incomplete privilege set was accepted: %v", err)
	}
	_, err = validateScopedRoleJSON([]byte(`[{"roleid":"BoetticherProvisioner","privs":"VM.Audit","special":1}]`), "BoetticherProvisioner", wanted)
	if err == nil || !strings.Contains(err.Error(), "special privileges") {
		t.Fatalf("special role privileges were accepted: %v", err)
	}
}

func TestConfigureIdentitiesLocksProxmoxLabadminAndInstallsBoundedSudo(t *testing.T) {
	runner := &fakeRunner{}
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample operator"
	if err := ConfigureIdentities(context.Background(), runner, "192.0.2.10", "root", key, []string{"lab-fw-01:22"}); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"passwd --lock labadmin", "/etc/sudoers.d/boetticher-labadmin", "visudo -cf /etc/sudoers", "/bin/sh -c * /usr/bin/python3 /tmp/boetticher-ansible/ansible-tmp-*/*", "AllowUsers labadmin lab-jump", "Match User lab-jump"} {
		if !strings.Contains(runner.command, required) {
			t.Fatalf("identity bootstrap missing %q: %s", required, runner.command)
		}
	}
	if strings.Contains(runner.command, "NOPASSWD:ALL") {
		t.Fatal("Proxmox labadmin received unrestricted sudo")
	}
	for _, command := range []string{"/usr/bin/pvesh *", "/usr/bin/pvesm *"} {
		if !strings.Contains(runner.command, command) {
			t.Fatalf("Proxmox labadmin sudo policy is missing %s", command)
		}
	}
}

func TestCheckBuilderCapacityHoldsBelowMinimum(t *testing.T) {
	runner := &fakeRunner{output: []byte("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 33554432 12582912 20971520 38% /\n")}
	if err := CheckBuilderCapacity(context.Background(), runner, "192.0.2.10", "labadmin", 20); err != nil {
		t.Fatalf("expected exact minimum builder capacity to pass: %v", err)
	}
	runner.output = []byte("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 33554432 12582912 10485760 69% /\n")
	if err := CheckBuilderCapacity(context.Background(), runner, "192.0.2.10", "labadmin", 20); err == nil || !strings.Contains(err.Error(), "HOLD") {
		t.Fatalf("insufficient builder capacity was not held: %v", err)
	}
}

func TestDiscoverPhysicalNetworkViaSSHUsesReadOnlyPveshEvidence(t *testing.T) {
	runner := &fakeRunner{responses: map[string][]byte{
		"pvesh get /nodes --output-format json": []byte(`[{"node":"proxmox"}]`),
		"pvesh get /nodes/proxmox/network --output-format json": []byte(`[
  {"iface":"vmbr0","type":"bridge","address":"192.0.2.73/24","gateway":"192.0.2.1","bridge_ports":"eno1"},
  {"iface":"vmbr1","type":"bridge","bridge_ports":"none","bridge_vlan_aware":true},
  {"iface":"eno1","type":"eth","hwaddr":"00:11:22:33:44:55","active":true},
  {"iface":"enp5s0","type":"eth","hwaddr":"00:aa:bb:cc:dd:ee","active":false}
	]`),
		"ip -j route show default": []byte(`[{"dev":"vmbr0"}]`),
	}}
	discovery, err := DiscoverPhysicalNetworkViaSSH(context.Background(), runner, "192.0.2.73", "root", "192.0.2.73", "", "")
	if err != nil || discovery.Node != "proxmox" || discovery.Discovery.Mode != "physical-trunk" || discovery.Discovery.Trunk == nil || discovery.Discovery.Trunk.Name != "enp5s0" {
		t.Fatalf("unexpected SSH discovery: %#v, %v", discovery, err)
	}
	if len(runner.commands) != 3 || runner.commands[0] != "pvesh get /nodes --output-format json" || runner.commands[1] != "pvesh get /nodes/proxmox/network --output-format json" || runner.commands[2] != "ip -j route show default" {
		t.Fatalf("unexpected discovery commands: %#v", runner.commands)
	}
}

func TestDiscoverPhysicalNetworkViaSSHResolvesSafeSingleNode(t *testing.T) {
	for _, node := range []string{"proxmox", "pve", "my-node_01.example"} {
		runner := &fakeRunner{responses: map[string][]byte{
			"pvesh get /nodes --output-format json":                      []byte(`[{"node":"` + node + `"}]`),
			"pvesh get /nodes/" + node + "/network --output-format json": []byte(`[{"iface":"vmbr0","type":"bridge","address":"192.0.2.73/24","gateway":"192.0.2.1","bridge_ports":"eno1"},{"iface":"eno1","type":"eth","hwaddr":"00:11:22:33:44:55","active":true}]`),
			"ip -j route show default":                                   []byte(`[{"dev":"vmbr0"}]`),
		}}
		resolved, err := DiscoverPhysicalNetworkViaSSH(context.Background(), runner, "192.0.2.73", "root", "192.0.2.73", "", "")
		if err != nil || resolved.Node != node {
			t.Fatalf("node %q was not resolved: %#v, %v", node, resolved, err)
		}
	}
}

func TestDiscoverPhysicalNetworkViaSSHHoldsAmbiguousOrMalformedNodeListing(t *testing.T) {
	for _, listing := range []string{"[]", `[{"node":"proxmox"},{"node":"pve02"}]`, `[{"node":"bad/node"}]`, "not-json"} {
		runner := &fakeRunner{responses: map[string][]byte{"pvesh get /nodes --output-format json": []byte(listing)}}
		if _, err := DiscoverPhysicalNetworkViaSSH(context.Background(), runner, "192.0.2.73", "root", "192.0.2.73", "", ""); err == nil || !strings.Contains(err.Error(), "HOLD") {
			t.Fatalf("listing %q did not hold: %v", listing, err)
		}
	}
}

func TestDiscoverPhysicalNetworkViaSSHHoldsNetworkQueryFailure(t *testing.T) {
	runner := &fakeRunner{
		responses: map[string][]byte{"pvesh get /nodes --output-format json": []byte(`[{"node":"proxmox"}]`)},
		errors:    map[string]error{"pvesh get /nodes/proxmox/network --output-format json": errors.New("permission denied")},
	}
	if _, err := DiscoverPhysicalNetworkViaSSH(context.Background(), runner, "192.0.2.73", "root", "192.0.2.73", "", ""); err == nil || !strings.Contains(err.Error(), "physical network") {
		t.Fatalf("network query failure was not held clearly: %v", err)
	}
}

func TestDiscoverPhysicalNetworkViaSSHUsesNonRootSudoWithoutPrompt(t *testing.T) {
	runner := &fakeRunner{responses: map[string][]byte{
		"sudo -n pvesh get /nodes --output-format json":                 []byte(`[{"node":"proxmox"}]`),
		"sudo -n pvesh get /nodes/proxmox/network --output-format json": []byte(`[{"iface":"vmbr0","type":"bridge","address":"192.0.2.73/24","gateway":"192.0.2.1","bridge_ports":"eno1"},{"iface":"eno1","type":"eth","hwaddr":"00:11:22:33:44:55","active":true}]`),
		"sudo -n ip -j route show default":                              []byte(`[{"dev":"vmbr0"}]`),
	}}
	if _, err := DiscoverPhysicalNetworkViaSSH(context.Background(), runner, "192.0.2.73", "dave", "192.0.2.73", "", ""); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverPhysicalNetworkViaSSHHoldsWhenNonRootSudoIsUnavailable(t *testing.T) {
	runner := &fakeRunner{errors: map[string]error{
		"sudo -n pvesh get /nodes --output-format json": errors.New("sudo: a password is required"),
	}}
	if _, err := DiscoverPhysicalNetworkViaSSH(context.Background(), runner, "192.0.2.73", "dave", "192.0.2.73", "", ""); err == nil || !strings.Contains(err.Error(), "must be root or have non-interactive sudo") {
		t.Fatalf("missing sudo did not produce a clear HOLD: %v", err)
	}
}

func TestConfigureIdentitiesUsesNonInteractiveSudoForNonRoot(t *testing.T) {
	runner := &fakeRunner{}
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample operator"
	if err := ConfigureIdentities(context.Background(), runner, "192.0.2.10", "dave", key, []string{"lab-fw-01:22"}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(runner.command, "sudo -n sh -c ") {
		t.Fatalf("root-required identity setup did not use non-interactive sudo: %q", runner.command)
	}
}

func TestCreateScopedCredentialsUsesNonInteractiveSudoForNonRoot(t *testing.T) {
	runner := &fakeRunner{
		output: []byte(`{"value":"opaque-token-secret"}`),
		responses: map[string][]byte{
			"sudo -n pvesh get /access/roles --output-format json":                      []byte(`[]`),
			"sudo -n pvesh get /access/users --output-format json":                      []byte(`[]`),
			"sudo -n pvesh get /access/users/'labadmin@pve'/token --output-format json": []byte(`[]`),
		},
	}
	secret, err := CreateScopedCredentialsWithRole(context.Background(), runner, "192.0.2.10", "dave", "labadmin@pve", "boetticher", "BoetticherProvisioner")
	if err != nil || secret != "opaque-token-secret" {
		t.Fatalf("CreateScopedCredentialsWithRole() = %q, %v", secret, err)
	}
	for _, command := range runner.commands {
		if strings.Contains(command, "pvesh") && !strings.HasPrefix(command, "sudo -n ") {
			t.Fatalf("privileged credential command ran without non-interactive sudo: %q", command)
		}
	}
}
