package proxmox

import (
	"context"
	"errors"
	"io"
	"os"
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

func TestQuoteRemoteArgsPreventsSecondRemoteCommand(t *testing.T) {
	quoted := quoteRemoteArgs([]string{"journalctl", "_HOSTNAME=retained;id"})
	if len(quoted) != 2 || quoted[1] != "'_HOSTNAME=retained;id'" {
		t.Fatalf("remote arguments were not shell-quoted: %#v", quoted)
	}
}

func TestSSHRunnerUsesBoundedTrustOnFirstUseForFreshApplianceHostKeys(t *testing.T) {
	runner := SSHRunner{StrictHostKey: "yes", HostAlias: "lab-dns-01"}
	args, err := runner.commandArgs("10.10.10.10", "labadmin", []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "StrictHostKeyChecking=yes") {
		t.Fatalf("fresh appliance probe does not require a pinned host key: %#v", args)
	}
	if strings.Contains(joined, "StrictHostKeyChecking=no") {
		t.Fatalf("fresh appliance probe disables host-key verification: %#v", args)
	}
}

func TestReadGuestHostKeyUsesAuthenticatedProxmoxBoundary(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA guest\n"
	for _, test := range []struct {
		kind   GuestKind
		output []byte
		want   string
	}{
		{kind: KindQEMU, output: []byte(`{"exited":1,"exitcode":0,"out-data":"` + key[:len(key)-1] + `\n"}`), want: strings.TrimSpace(strings.TrimSuffix(key, " guest\n"))},
		{kind: KindLXC, output: []byte(key), want: strings.TrimSpace(strings.TrimSuffix(key, " guest\n"))},
	} {
		runner := &fakeRunner{output: test.output}
		got, err := ReadGuestHostKey(context.Background(), runner, "192.0.2.10", "root", test.kind, 100)
		if err != nil {
			t.Fatalf("ReadGuestHostKey(%s) = %v", test.kind, err)
		}
		if got != test.want || !strings.Contains(runner.command, "/bin/cat /var/lib/boetticher/identity/ssh/ssh_host_ed25519_key.pub") {
			t.Fatalf("ReadGuestHostKey(%s) = %q, command %q", test.kind, got, runner.command)
		}
	}
}

func TestReadBuilderHostKeyUsesAuthenticatedHostBoundaryForNonRoot(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA builder\n"
	runner := &fakeRunner{output: []byte(`{"exited":1,"exitcode":0,"out-data":"` + strings.TrimSuffix(key, " builder\n") + `\n"}`)}
	got, err := ReadBuilderHostKey(context.Background(), runner, "192.0.2.10", "labadmin", 190)
	if err != nil {
		t.Fatal(err)
	}
	if got != strings.TrimSuffix(key, " builder\n") {
		t.Fatalf("ReadBuilderHostKey() = %q", got)
	}
	if !strings.Contains(runner.command, "sudo -n /usr/sbin/qm guest exec 190 -- /bin/cat /etc/ssh/ssh_host_ed25519_key.pub") {
		t.Fatalf("builder host key was not read through the authenticated host boundary: %q", runner.command)
	}
}

func TestSSHRunnerRejectsExecutableConfigBeforeStartingSSH(t *testing.T) {
	path := t.TempDir() + "/boetticher.conf"
	if err := os.WriteFile(path, []byte("Host lab-dns-01\n    LocalCommand id\n"), 0600); err != nil {
		t.Fatal(err)
	}
	runner := SSHRunner{ConfigFile: path}
	if err := runner.validateConfig(); err == nil {
		t.Fatal("executable SSH directive was not rejected")
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
	args, err := runner.commandArgs("10.10.10.10", "labadmin", []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(args, "labadmin@lab-dns-01") || !containsString(args, "HostKeyAlias=lab-proxmox-01") {
		t.Fatalf("appliance HostAlias and independent HostKeyAlias were not preserved: %#v", args)
	}
}

func TestSSHRunnerLocalForwardUsesLoopbackAndBoundedTarget(t *testing.T) {
	runner := SSHRunner{ConfigFile: "/tmp/boetticher.conf", StrictHostKey: "accept-new", HostAlias: "lab-proxmox-01"}
	args, err := runner.forwardArgs("192.0.2.10", "root", 43123, "10.10.10.20", 443)
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(args, "-N") || !containsString(args, "-L") || !containsString(args, "127.0.0.1:43123:10.10.10.20:443") {
		t.Fatalf("local forward is not loopback-only or target-bounded: %#v", args)
	}
	if !containsString(args, "BatchMode=yes") || !containsString(args, "ExitOnForwardFailure=yes") || !containsString(args, "root@lab-proxmox-01") {
		t.Fatalf("local forward does not use non-interactive Proxmox SSH: %#v", args)
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

func TestCheckScopedCredentialAvailabilityHoldsExistingToken(t *testing.T) {
	runner := &fakeRunner{responses: map[string][]byte{
		"pvesh get /access/roles --output-format json":                      []byte(`[]`),
		"pvesh get /access/users --output-format json":                      []byte(`[{"userid":"labadmin@pve"}]`),
		"pvesh get /access/users/'labadmin@pve'/token --output-format json": []byte(`[{"tokenid":"boetticher"}]`),
	}}
	err := CheckScopedCredentialAvailability(context.Background(), runner, "192.0.2.10", "root", "labadmin@pve", "boetticher", "BoetticherProvisioner")
	if err == nil || !strings.Contains(err.Error(), "HOLD") || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing reserved token was not held: %v", err)
	}
	for _, command := range runner.commands {
		if strings.Contains(command, " create ") || strings.Contains(command, " set ") || strings.Contains(command, " delete ") {
			t.Fatalf("credential reservation check mutated Proxmox: %s", command)
		}
	}
}

func TestCheckScopedCredentialReuseAcceptsExistingBoundedToken(t *testing.T) {
	runner := &fakeRunner{responses: map[string][]byte{
		"pvesh get /access/roles --output-format json":                      []byte(`[{"roleid":"BoetticherProvisioner","privs":"VM.Allocate VM.Audit VM.Config.CDROM VM.Config.CPU VM.Config.Cloudinit VM.Config.Disk VM.Config.HWType VM.Config.Memory VM.Config.Network VM.Config.Options VM.GuestAgent.Audit VM.PowerMgmt Datastore.Allocate Datastore.AllocateSpace Datastore.AllocateTemplate Datastore.Audit SDN.Audit SDN.Use Sys.AccessNetwork Sys.Audit Sys.Modify","special":0}]`),
		"pvesh get /access/users --output-format json":                      []byte(`[{"userid":"labadmin@pve"}]`),
		"pvesh get /access/users/'labadmin@pve'/token --output-format json": []byte(`[{"tokenid":"boetticher"}]`),
	}}
	if err := CheckScopedCredentialReuse(context.Background(), runner, "192.0.2.10", "root", "labadmin@pve", "boetticher", "BoetticherProvisioner"); err != nil {
		t.Fatalf("existing bounded token was not accepted for encrypted-credential reuse: %v", err)
	}
	for _, command := range runner.commands {
		if strings.Contains(command, " create ") || strings.Contains(command, " set ") || strings.Contains(command, " delete ") {
			t.Fatalf("credential reuse check mutated Proxmox: %s", command)
		}
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
	var userACL, tokenACL bool
	for _, command := range runner.commands {
		if strings.Contains(command, "pvesh create /access/roles") {
			if !strings.Contains(command, "pvesh create /access/roles --roleid 'BoetticherProvisioner'") {
				t.Fatalf("role creation used the wrong Proxmox API shape: %s", command)
			}
		}
		if strings.Contains(command, "pvesh set /access/acl") && strings.Contains(command, "--users 'labadmin@pve'") && strings.Contains(command, "--roles 'BoetticherProvisioner'") {
			userACL = true
		}
		if strings.Contains(command, "pvesh set /access/acl") && strings.Contains(command, "--tokens 'labadmin@pve!boetticher'") && strings.Contains(command, "--roles 'BoetticherProvisioner'") {
			tokenACL = true
		}
	}
	if !userACL || !tokenACL {
		t.Fatalf("credential bootstrap ACLs incomplete: user=%t token=%t commands=%v", userACL, tokenACL, runner.commands)
	}
}

func TestEnsureScopedCredentialACLRepairsBackingUserAndToken(t *testing.T) {
	runner := &fakeRunner{}
	if err := EnsureScopedCredentialACL(context.Background(), runner, "192.0.2.10", "root", "labadmin@pve", "boetticher", "BoetticherProvisioner"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"pvesh set /access/acl --path / --users 'labadmin@pve' --roles 'BoetticherProvisioner' --propagate 1",
		"pvesh set /access/acl --path / --tokens 'labadmin@pve!boetticher' --roles 'BoetticherProvisioner' --propagate 1",
	}
	if !reflect.DeepEqual(runner.commands, want) {
		t.Fatalf("scoped credential ACL repair commands = %#v, want %#v", runner.commands, want)
	}
}

func TestCreatePulseMonitoringCredentialsUsesBoundedAPIOnlyIdentity(t *testing.T) {
	runner := &fakeRunner{
		responses: map[string][]byte{
			"pvesh get /access/roles --output-format json":                                                                  []byte(`[{"roleid":"PVEAuditor","privs":"Datastore.Audit Mapping.Audit Pool.Audit SDN.Audit Sys.Audit VM.Audit VM.GuestAgent.Audit","special":1}]`),
			"pvesh get /access/users --output-format json":                                                                  []byte(`[]`),
			"pvesh get /access/users/'pulse-monitor@pve'/token --output-format json":                                        []byte(`[]`),
			"pvesh create /access/users/'pulse-monitor@pve'/token/'boetticher-monitoring' --privsep 1 --output-format json": []byte(`{"value":"opaque-monitoring-secret"}`),
		},
		output: []byte(`{"value":"opaque-monitoring-secret"}`),
	}
	secret, err := CreatePulseMonitoringCredentials(context.Background(), runner, "192.0.2.10", "root")
	if err != nil {
		t.Fatal(err)
	}
	if secret != "opaque-monitoring-secret" {
		t.Fatalf("CreatePulseMonitoringCredentials() returned %q", secret)
	}
	joined := strings.Join(runner.commands, "\n")
	for _, required := range []string{
		"pvesh create /access/users --userid 'pulse-monitor@pve'",
		"pvesh create /access/users/'pulse-monitor@pve'/token/'boetticher-monitoring' --privsep 1 --output-format json",
		"pvesh set /access/acl --path '/' --users 'pulse-monitor@pve' --roles 'PVEAuditor' --propagate 1",
		"pvesh set /access/acl --path '/' --tokens 'pulse-monitor@pve!boetticher-monitoring' --roles 'PVEAuditor' --propagate 1",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("Pulse monitoring bootstrap is missing %q:\n%s", required, joined)
		}
	}
	for _, forbidden := range []string{"root@pam", "BoetticherProvisioner", "VM.Monitor", "VM.GuestAgent", "PVEDatastoreAdmin", "/storage", "ssh", "opaque-monitoring-secret"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("Pulse monitoring bootstrap contains forbidden %q:\n%s", forbidden, joined)
		}
	}
}

func TestCreatePulseMonitoringCredentialsFailsClosedWhenAuditorRoleIsMissing(t *testing.T) {
	runner := &fakeRunner{responses: map[string][]byte{
		"pvesh get /access/roles --output-format json": []byte(`[]`),
	}}
	if _, err := CreatePulseMonitoringCredentials(context.Background(), runner, "192.0.2.10", "root"); err == nil || !strings.Contains(err.Error(), "PVEAuditor") {
		t.Fatalf("missing auditor role was not rejected: %v", err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("role failure continued into mutation: %#v", runner.commands)
	}
}

func TestCreatePulseMonitoringCredentialsRejectsExpandedAuditorRole(t *testing.T) {
	runner := &fakeRunner{responses: map[string][]byte{
		"pvesh get /access/roles --output-format json": []byte(`[{"roleid":"PVEAuditor","privs":"Datastore.Audit Mapping.Audit Pool.Audit SDN.Audit Sys.Audit VM.Audit VM.GuestAgent.Audit VM.Allocate","special":1}]`),
	}}
	if _, err := CreatePulseMonitoringCredentials(context.Background(), runner, "192.0.2.10", "root"); err == nil || !strings.Contains(err.Error(), "privileges") {
		t.Fatalf("expanded auditor role was not rejected: %v", err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("role failure continued into mutation: %#v", runner.commands)
	}
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

func TestConfigureIdentitiesInstallsTemporaryRootAccessWithoutLabadminSudo(t *testing.T) {
	runner := &fakeRunner{}
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample operator"
	if err := ConfigureIdentities(context.Background(), runner, "192.0.2.10", "root", key, []string{"10.10.99.1:22", "10.10.10.20:443"}); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"passwd --lock labadmin", "/root/.ssh/authorized_keys", "rm -f /etc/sudoers.d/boetticher-labadmin", "visudo -cf /etc/sudoers", "chown lab-jump:lab-jump /home/lab-jump.authorized_keys", "AllowUsers root labadmin lab-jump", "Match User lab-jump"} {
		if !strings.Contains(runner.command, required) {
			t.Fatalf("identity bootstrap missing %q: %s", required, runner.command)
		}
	}
	for _, forbidden := range []string{"NOPASSWD", "/usr/bin/pvesh *", "/usr/bin/pvesm *", "/bin/sh -c *", "/usr/bin/install *", "/usr/bin/chown *", "/usr/bin/chmod *"} {
		if strings.Contains(runner.command, forbidden) {
			t.Fatalf("identity bootstrap retained durable wildcard privilege %q: %s", forbidden, runner.command)
		}
	}
}

func TestRestoreTemporaryRootAccessUsesExactOwnedGuestBoundary(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample operator"
	for _, guest := range []struct {
		kind GuestKind
		vmid int
		want string
	}{
		{kind: KindQEMU, vmid: 100, want: "/usr/sbin/qm guest exec 100 -- /bin/sh -c"},
		{kind: KindLXC, vmid: 110, want: "/usr/sbin/pct exec 110 -- /bin/sh -c"},
	} {
		t.Run(string(guest.kind), func(t *testing.T) {
			runner := &fakeRunner{output: []byte("{\"exitcode\":0,\"exited\":1}")}
			if err := RestoreTemporaryRootAccess(context.Background(), runner, "192.0.2.10", "root", guest.kind, guest.vmid, key); err != nil {
				t.Fatal(err)
			}
			if runner.user != "root" || !strings.Contains(runner.command, guest.want) {
				t.Fatalf("temporary root restore used unexpected host command: %#v", runner)
			}
			for _, forbidden := range []string{"sudo", "rm -rf", "StrictHostKeyChecking=no"} {
				if strings.Contains(runner.command, forbidden) {
					t.Fatalf("temporary root restore contains forbidden %q: %s", forbidden, runner.command)
				}
			}
			if !strings.Contains(runner.command, "/root/.ssh/authorized_keys") || !strings.Contains(runner.command, "grep -qxF") {
				t.Fatalf("temporary root restore did not install the exact key idempotently: %s", runner.command)
			}
		})
	}
}

func TestRestoreTemporaryRootAccessRejectsGuestAgentFailure(t *testing.T) {
	runner := &fakeRunner{output: []byte("{\"exitcode\":1,\"exited\":1,\"err-data\":\"permission denied\"}")}
	err := RestoreTemporaryRootAccess(context.Background(), runner, "192.0.2.10", "root", KindQEMU, 100, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample operator")
	if err == nil || !strings.Contains(err.Error(), "exited 1") {
		t.Fatalf("guest-agent failure was not preserved: %v", err)
	}
}

func TestRevokeTemporaryRootAccessIsFixedAndIdempotent(t *testing.T) {
	for _, host := range []bool{false, true} {
		runner := &fakeRunner{}
		if err := RevokeTemporaryRootAccess(context.Background(), runner, "192.0.2.10", "root", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample operator", host); err != nil {
			t.Fatal(err)
		}
		if runner.user != "root" {
			t.Fatalf("temporary cleanup used %q instead of root", runner.user)
		}
		if strings.Contains(runner.command, "sudo") || strings.Contains(runner.command, "pvesh") || strings.Contains(runner.command, "pvesm") || strings.Contains(runner.command, "sh -c") {
			t.Fatalf("temporary cleanup exposed an unrelated privilege path: %s", runner.command)
		}
		if host && !strings.Contains(runner.command, "AllowUsers root labadmin lab-jump") {
			t.Fatalf("host cleanup does not verify the temporary AllowUsers state: %s", runner.command)
		}
		for _, required := range []string{"grep -Fvx --", "authorized_keys.boetticher-cleanup", "passwd --lock root"} {
			if !strings.Contains(runner.command, required) {
				t.Fatalf("temporary cleanup does not remove only the injected key: missing %q in %s", required, runner.command)
			}
		}
	}
	if err := RevokeTemporaryRootAccess(context.Background(), &fakeRunner{}, "192.0.2.10", "labadmin", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample operator", false); err == nil {
		t.Fatal("temporary cleanup accepted a non-root transport")
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
	if err := ConfigureIdentities(context.Background(), runner, "192.0.2.10", "dave", key, []string{"10.10.99.1:22"}); err != nil {
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
