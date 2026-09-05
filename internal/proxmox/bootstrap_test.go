package proxmox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
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

type staleScopedTokenRunner struct {
	commands []string
	removed  bool
	scoped   bool
}

type stalePulseMonitoringTokenRunner struct {
	commands []string
	removed  bool
}

func (r *staleScopedTokenRunner) Run(_ context.Context, _ string, _ string, command string) ([]byte, error) {
	r.commands = append(r.commands, command)
	switch command {
	case "pvesh get /access/roles --output-format json":
		return []byte(`[{"roleid":"BoetticherProvisioner","privs":"` + ScopedProvisionerPrivileges() + `","special":0}]`), nil
	case "pvesh get /access/users --output-format json":
		return []byte(`[{"comment":"boetticher automation identity","enable":1,"expire":0,"userid":"labadmin@pve"}]`), nil
	case "pvesh get /access/users/'labadmin@pve'/token --output-format json":
		if r.removed {
			return []byte(`[]`), nil
		}
		return []byte(`[{"expire":0,"privsep":1,"tokenid":"boetticher"}]`), nil
	case "pvesh get /access/acl --output-format json":
		if r.scoped {
			acls := []scopedCredentialACLEntry{}
			for _, subject := range []struct{ value, typ string }{{"labadmin@pve", "user"}, {"labadmin@pve!boetticher", "token"}} {
				for _, path := range scopedProvisionerACLPaths("node") {
					acls = append(acls, scopedCredentialACLEntry{Path: path, Propagate: scopedProvisionerACLPropagate(path), RoleID: "BoetticherProvisioner", Type: subject.typ, UGID: subject.value})
				}
			}
			data, _ := json.Marshal(acls)
			return data, nil
		}
		return []byte(`[{"path":"/","propagate":1,"roleid":"BoetticherProvisioner","type":"user","ugid":"labadmin@pve"},{"path":"/","propagate":1,"roleid":"BoetticherProvisioner","type":"token","ugid":"labadmin@pve!boetticher"}]`), nil
	case "pvesh delete /access/acl --path / --users 'labadmin@pve' --roles 'BoetticherProvisioner'", "pvesh delete /access/acl --path / --tokens 'labadmin@pve!boetticher' --roles 'BoetticherProvisioner'":
		return nil, nil
	case "pvesh delete /access/users/'labadmin@pve'/token/'boetticher'":
		r.removed = true
		return nil, nil
	default:
		return nil, errors.New("unexpected command: " + command)
	}
}

func (r *stalePulseMonitoringTokenRunner) Run(_ context.Context, _ string, _ string, command string) ([]byte, error) {
	r.commands = append(r.commands, command)
	switch command {
	case "pvesh get /access/roles --output-format json":
		return []byte(`[{"roleid":"PVEAuditor","privs":"Datastore.Audit Mapping.Audit Pool.Audit SDN.Audit Sys.Audit VM.Audit VM.GuestAgent.Audit","special":1}]`), nil
	case "pvesh get /access/users --output-format json":
		return []byte(`[{"comment":"Pulse API-only monitoring identity","enable":1,"expire":0,"userid":"pulse-monitor@pve"}]`), nil
	case "pvesh get /access/users/'pulse-monitor@pve'/token --output-format json":
		if r.removed {
			return []byte(`[]`), nil
		}
		return []byte(`[{"expire":0,"privsep":1,"tokenid":"boetticher-monitoring"}]`), nil
	case "pvesh get /access/acl --output-format json":
		return []byte(`[{"path":"/","propagate":1,"roleid":"PVEAuditor","type":"user","ugid":"pulse-monitor@pve"},{"path":"/","propagate":1,"roleid":"PVEAuditor","type":"token","ugid":"pulse-monitor@pve!boetticher-monitoring"}]`), nil
	case "pvesh delete /access/users/'pulse-monitor@pve'/token/'boetticher-monitoring'":
		r.removed = true
		return nil, nil
	case "pvesh create /access/users/'pulse-monitor@pve'/token/'boetticher-monitoring' --privsep 1 --output-format json":
		return []byte(`{"value":"recreated-monitoring-secret"}`), nil
	case "pvesh set /access/acl --path '/' --users 'pulse-monitor@pve' --roles 'PVEAuditor' --propagate 1", "pvesh set /access/acl --path '/' --tokens 'pulse-monitor@pve!boetticher-monitoring' --roles 'PVEAuditor' --propagate 1":
		return nil, nil
	default:
		return nil, errors.New("unexpected command: " + command)
	}
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
	if !strings.Contains(joined, "ConnectTimeout=10") {
		t.Fatalf("fresh appliance probe does not have a bounded SSH connection timeout: %#v", args)
	}
	if strings.Contains(joined, "StrictHostKeyChecking=no") {
		t.Fatalf("fresh appliance probe disables host-key verification: %#v", args)
	}
}

func TestSSHRunnerFreshConnectionBypassesMultiplexing(t *testing.T) {
	runner := (SSHRunner{StrictHostKey: "yes", HostAlias: "lab-dns-01"}).FreshConnection()
	args, err := runner.commandArgs("10.10.10.10", "root", []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "ControlMaster=no") || !strings.Contains(joined, "ControlPath=none") {
		t.Fatalf("fresh authentication probe can reuse an existing control master: %#v", args)
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
	runner := SSHRunner{StrictHostKey: "yes", HostKeyAlias: "lab-proxmox-01"}
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

func TestSSHRunnerRestrictsAuthenticationToConfiguredIdentity(t *testing.T) {
	runner := SSHRunner{IdentityFile: "/tmp/operator", StrictHostKey: "yes"}
	args, err := runner.commandArgs("192.0.2.10", "root", []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(args, "IdentitiesOnly=yes") || !containsString(args, "-i") || !containsString(args, "/tmp/operator") {
		t.Fatalf("SSH runner did not restrict authentication to the configured identity: %#v", args)
	}
}

func TestSSHRunnerRejectsSymlinkedTrustPaths(t *testing.T) {
	dir := t.TempDir()
	external := t.TempDir()
	if err := os.Symlink(external, filepath.Join(dir, "known-hosts")); err != nil {
		t.Fatal(err)
	}
	runner := SSHRunner{KnownHosts: filepath.Join(dir, "known-hosts", "hosts"), StrictHostKey: "yes"}
	if err := runner.validateConfig(); err == nil || !strings.Contains(err.Error(), "known-hosts") {
		t.Fatalf("symlinked known-hosts parent was accepted: %v", err)
	}
	if err := os.Symlink(external, filepath.Join(dir, "identity")); err != nil {
		t.Fatal(err)
	}
	runner = SSHRunner{IdentityFile: filepath.Join(dir, "identity", "id_ed25519"), StrictHostKey: "yes"}
	if err := runner.validateConfig(); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("symlinked identity parent was accepted: %v", err)
	}
}

func TestSSHRunnerUsesInMemoryIdentityOnInheritedDescriptor(t *testing.T) {
	identity := []byte("temporary private key")
	runner := (SSHRunner{StrictHostKey: "yes"}).WithIdentityData(identity)
	args, err := runner.commandArgs("192.0.2.10", "root", []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(args, "IdentitiesOnly=yes") || !containsString(args, "/dev/fd/3") {
		t.Fatalf("in-memory identity did not use the inherited descriptor: %#v", args)
	}
	if containsString(args, "temporary private key") || runner.IdentityFile != "" {
		t.Fatalf("temporary identity leaked into SSH arguments or persistent file configuration: %#v", args)
	}
	runner.ClearIdentityData()
	if len(runner.identityData) != 0 {
		t.Fatal("ClearIdentityData retained operation-scoped key material")
	}
}

func TestSSHRunnerIsolatesTargetIdentityButPreservesProxyJumpIdentity(t *testing.T) {
	path := t.TempDir() + "/boetticher.conf"
	config := "Host lab-bastion\n    IdentityFile /tmp/operator\n    ControlMaster auto\n    ControlPersist 60\n    ControlPath ~/.ssh/control-%C\nHost lab-dns-01\n    IdentityFile /tmp/operator\n    ProxyJump lab-bastion\n"
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	runner := SSHRunner{ConfigFile: path, HostAlias: "lab-dns-01"}
	filtered, err := runner.isolatedSSHConfig()
	if err != nil {
		t.Fatal(err)
	}
	text := string(filtered)
	if strings.Count(text, "IdentityFile /tmp/operator") != 1 || !strings.Contains(text, "Host lab-bastion") || !strings.Contains(text, "ProxyJump lab-bastion") {
		t.Fatalf("isolated SSH configuration lost the bastion identity or retained the target identity: %s", text)
	}
	if !strings.Contains(text, "ControlMaster no") || !strings.Contains(text, "ControlPath none") || strings.Contains(text, "ControlPersist 60") {
		t.Fatalf("isolated SSH configuration retained bastion multiplexing: %s", text)
	}
}

func TestSSHRunnerStreamsTemporaryIdentityAndConfigToProcess(t *testing.T) {
	fakeBin := t.TempDir()
	capture := t.TempDir() + "/capture"
	fakeSSH := "#!/bin/sh\nset -eu\nconfig=\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"-F\" ]; then config=$2; shift; fi\n  shift\ndone\nprintf '%s' \"$config\" > \"$BOETTICHER_TEST_CAPTURE.path\"\ncat /dev/fd/3 > \"$BOETTICHER_TEST_CAPTURE.identity\"\ncat \"$config\" > \"$BOETTICHER_TEST_CAPTURE.config\"\nprintf '%s\\n' ready\n"
	if err := os.WriteFile(fakeBin+"/ssh", []byte(fakeSSH), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+":"+os.Getenv("PATH"))
	t.Setenv("BOETTICHER_TEST_CAPTURE", capture)
	previousSSH := sshExecutable
	sshExecutable = filepath.Join(fakeBin, "ssh")
	t.Cleanup(func() { sshExecutable = previousSSH })
	configPath := t.TempDir() + "/boetticher.conf"
	config := "Host lab-bastion\n    IdentityFile /tmp/operator\nHost lab-dns-01\n    IdentityFile /tmp/operator\n    ProxyJump lab-bastion\n"
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	identity := []byte("temporary private key")
	runner := (SSHRunner{ConfigFile: configPath, HostAlias: "lab-dns-01", StrictHostKey: "yes"}).WithIdentityData(identity)
	var output bytes.Buffer
	if err := runner.RunStream(context.Background(), "10.10.10.10", "root", "true", &output); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(output.String()) != "ready" {
		t.Fatalf("fake SSH process output = %q", output.String())
	}
	identityData, err := os.ReadFile(capture + ".identity")
	if err != nil || string(identityData) != string(identity) {
		t.Fatalf("temporary identity was not streamed through the inherited descriptor: err=%v", err)
	}
	configData, err := os.ReadFile(capture + ".config")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(configData), "IdentityFile /tmp/operator") != 1 || !strings.Contains(string(configData), "Host lab-bastion") {
		t.Fatal("isolated config did not preserve only the bastion identity")
	}
	temporaryPath, err := os.ReadFile(capture + ".path")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(string(temporaryPath)); !os.IsNotExist(err) {
		t.Fatalf("temporary SSH configuration remains after the operation: %v", err)
	}
}

func TestSSHProcessUsesDedicatedProcessGroupForProxyJumpCleanup(t *testing.T) {
	process := newSSHProcess([]string{"true"})
	if process.SysProcAttr == nil || !process.SysProcAttr.Setpgid {
		t.Fatal("SSH process is not isolated for process-group cancellation")
	}
}

func TestSSHRunnerLocalForwardUsesLoopbackAndBoundedTarget(t *testing.T) {
	runner := SSHRunner{ConfigFile: "/tmp/boetticher.conf", StrictHostKey: "yes", HostAlias: "lab-proxmox-01"}
	args, err := runner.forwardArgs("192.0.2.10", "root", 43123, "10.10.10.20", 443)
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(args, "-N") || !containsString(args, "-L") || !containsString(args, "127.0.0.1:43123:10.10.10.20:443") {
		t.Fatalf("local forward is not loopback-only or target-bounded: %#v", args)
	}
	if !containsString(args, "BatchMode=yes") || !containsString(args, "ControlMaster=no") || !containsString(args, "ControlPath=none") || !containsString(args, "ExitOnForwardFailure=yes") || !containsString(args, "root@lab-proxmox-01") {
		t.Fatalf("local forward does not use non-interactive Proxmox SSH: %#v", args)
	}
}

func TestSSHRunnerRejectsWeakHostKeyVerificationModes(t *testing.T) {
	for _, mode := range []string{"no", "accept-new"} {
		if _, err := (SSHRunner{StrictHostKey: mode}).commandArgs("192.0.2.10", "root", []string{"true"}); err == nil {
			t.Fatalf("weak SSH host-key mode %q was accepted", mode)
		}
	}
}

func TestConfigureManagementNetworkValidatesUnchangedHOMEAndVLANState(t *testing.T) {
	runner := &fakeRunner{responses: map[string][]byte{
		"sudo -n /bin/cat /etc/network/interfaces":        []byte("auto vmbr0\niface vmbr0 inet static\n"),
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
		"sudo -n /bin/cat /etc/network/interfaces",
		"sudo -n install -D -m 0644 /dev/stdin /etc/network/interfaces",
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

func (f *fakeRunner) RunWithStdin(ctx context.Context, address, user, command string, _ io.Reader) ([]byte, error) {
	return f.Run(ctx, address, user, command)
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func TestInstallTemporaryRootAccessUsesIndependentRecoveryTransport(t *testing.T) {
	runner := &fakeRunner{}
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample boetticher-apply"
	if err := InstallTemporaryRootAccess(context.Background(), runner, "192.0.2.10", "root", key); err != nil {
		t.Fatal(err)
	}
	if runner.user != "root" || !strings.Contains(runner.command, "/root/.ssh/authorized_keys") || !strings.Contains(runner.command, "grep -qxF") {
		t.Fatalf("temporary root acquisition used unexpected command: %#v", runner)
	}
	if strings.Contains(runner.command, "passwd") || strings.Contains(runner.command, "AllowUsers") || strings.Contains(runner.command, "sudo") {
		t.Fatalf("temporary root acquisition changed durable recovery policy: %s", runner.command)
	}
}

func TestRevokeTemporaryRootAccessThroughHostUsesExactOwnedGuestBoundary(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample boetticher-apply"
	for _, guest := range []struct {
		kind GuestKind
		vmid int
		want string
	}{
		{kind: KindQEMU, vmid: 100, want: "/usr/sbin/qm guest exec 100 -- /bin/sh -c"},
		{kind: KindLXC, vmid: 110, want: "/usr/sbin/pct exec 110 -- /bin/sh -c"},
	} {
		runner := &fakeRunner{output: []byte(`{"exitcode":0,"exited":1}`)}
		if err := RevokeTemporaryRootAccessThroughHost(context.Background(), runner, "192.0.2.10", "root", guest.kind, guest.vmid, key); err != nil {
			t.Fatalf("guest cleanup %s = %v", guest.kind, err)
		}
		if !strings.Contains(runner.command, guest.want) || !strings.Contains(runner.command, "/root/.ssh/authorized_keys") || !strings.Contains(runner.command, "grep -Fvx") {
			t.Fatalf("guest cleanup %s used an unexpected host command: %s", guest.kind, runner.command)
		}
		if strings.Contains(runner.command, "passwd") || strings.Contains(runner.command, "AllowUsers") {
			t.Fatalf("guest cleanup %s changed unrelated recovery state: %s", guest.kind, runner.command)
		}
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
	secret, err := CreateScopedCredentials(context.Background(), runner, "192.0.2.10", "root", "labadmin@pve", "boetticher", "node")
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

func TestRemoveExactScopedCredentialTokenDeletesOnlyTheOwnedToken(t *testing.T) {
	runner := &staleScopedTokenRunner{}
	removed, err := RemoveExactScopedCredentialToken(context.Background(), runner, "192.0.2.10", "root", "labadmin@pve", "boetticher", "BoetticherProvisioner", "node")
	if err != nil || !removed {
		t.Fatalf("RemoveExactScopedCredentialToken() = %t, %v", removed, err)
	}
	if !runner.removed {
		t.Fatal("exact scoped token was not removed")
	}
	deleteCommand := "pvesh delete /access/users/'labadmin@pve'/token/'boetticher'"
	if !containsString(runner.commands, deleteCommand) {
		t.Fatalf("expected exact token deletion command, got %#v", runner.commands)
	}
	if !containsString(runner.commands, "pvesh get /access/acl --output-format json") {
		t.Fatalf("token replacement did not prove scoped credential ACL ownership: %#v", runner.commands)
	}
	for _, command := range runner.commands {
		legacyUserACL := "pvesh delete /access/acl --path / --users 'labadmin@pve' --roles 'BoetticherProvisioner'"
		legacyTokenACL := "pvesh delete /access/acl --path / --tokens 'labadmin@pve!boetticher' --roles 'BoetticherProvisioner'"
		if strings.Contains(command, "pvesh delete ") && command != deleteCommand && command != legacyUserACL && command != legacyTokenACL {
			t.Fatalf("token replacement issued an unexpected deletion: %s", command)
		}
		for _, forbidden := range []string{"/access/users/'labadmin@pve' --", "/access/roles", "root@pam"} {
			if strings.Contains(command, "pvesh delete ") && strings.Contains(command, forbidden) {
				t.Fatalf("token replacement deletion touched forbidden target %q: %s", forbidden, command)
			}
		}
	}
}

func TestRemoveExactScopedCredentialTokenAcceptsNonPropagatingStorageCollection(t *testing.T) {
	runner := &staleScopedTokenRunner{scoped: true}
	removed, err := RemoveExactScopedCredentialToken(context.Background(), runner, "192.0.2.10", "root", "labadmin@pve", "boetticher", "BoetticherProvisioner", "node")
	if err != nil || !removed || !runner.removed {
		t.Fatalf("RemoveExactScopedCredentialToken() with scoped ACLs = %t, %v", removed, err)
	}
}

func TestRemoveExactScopedCredentialTokenRefusesUnexpectedOwnership(t *testing.T) {
	role := []byte(`[{"roleid":"BoetticherProvisioner","privs":"` + ScopedProvisionerPrivileges() + `","special":0}]`)
	for _, test := range []struct {
		name   string
		users  []byte
		tokens []byte
		acls   []byte
	}{
		{
			name:   "user metadata",
			users:  []byte(`[{"comment":"unexpected","enable":1,"expire":0,"userid":"labadmin@pve"}]`),
			tokens: []byte(`[{"expire":0,"privsep":1,"tokenid":"boetticher"}]`),
			acls:   []byte(`[{"path":"/","propagate":1,"roleid":"BoetticherProvisioner","type":"user","ugid":"labadmin@pve"},{"path":"/","propagate":1,"roleid":"BoetticherProvisioner","type":"token","ugid":"labadmin@pve!boetticher"}]`),
		},
		{
			name:   "token metadata",
			users:  []byte(`[{"comment":"boetticher automation identity","enable":1,"expire":0,"userid":"labadmin@pve"}]`),
			tokens: []byte(`[{"expire":0,"privsep":0,"tokenid":"boetticher"}]`),
			acls:   []byte(`[{"path":"/","propagate":1,"roleid":"BoetticherProvisioner","type":"user","ugid":"labadmin@pve"},{"path":"/","propagate":1,"roleid":"BoetticherProvisioner","type":"token","ugid":"labadmin@pve!boetticher"}]`),
		},
		{
			name:   "ACL",
			users:  []byte(`[{"comment":"boetticher automation identity","enable":1,"expire":0,"userid":"labadmin@pve"}]`),
			tokens: []byte(`[{"expire":0,"privsep":1,"tokenid":"boetticher"}]`),
			acls:   []byte(`[]`),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &fakeRunner{responses: map[string][]byte{
				"pvesh get /access/roles --output-format json":                      role,
				"pvesh get /access/users --output-format json":                      test.users,
				"pvesh get /access/users/'labadmin@pve'/token --output-format json": test.tokens,
				"pvesh get /access/acl --output-format json":                        test.acls,
			}}
			removed, err := RemoveExactScopedCredentialToken(context.Background(), runner, "192.0.2.10", "root", "labadmin@pve", "boetticher", "BoetticherProvisioner", "node")
			if err == nil || !strings.Contains(err.Error(), "ownership") {
				t.Fatalf("unexpected scoped credential ownership was accepted: removed=%t err=%v", removed, err)
			}
			for _, command := range runner.commands {
				if strings.Contains(command, "pvesh delete") {
					t.Fatalf("unexpected ownership triggered token deletion: %s", command)
				}
			}
		})
	}
}

func TestRemoveExactScopedCredentialTokenRefusesUnexpectedRole(t *testing.T) {
	runner := &fakeRunner{responses: map[string][]byte{
		"pvesh get /access/roles --output-format json": []byte(`[]`),
	}}
	if _, err := RemoveExactScopedCredentialToken(context.Background(), runner, "192.0.2.10", "root", "labadmin@pve", "boetticher", "BoetticherProvisioner", "node"); err == nil || !strings.Contains(err.Error(), "not present") {
		t.Fatalf("unexpected scoped role was accepted for token removal: %v", err)
	}
	for _, command := range runner.commands {
		if strings.Contains(command, "pvesh delete ") {
			t.Fatalf("unexpected role triggered token deletion: %s", command)
		}
	}
}

func TestCheckScopedCredentialReuseAcceptsExistingBoundedToken(t *testing.T) {
	runner := &fakeRunner{responses: map[string][]byte{
		"pvesh get /access/roles --output-format json":                      []byte(`[{"roleid":"BoetticherProvisioner","privs":"VM.Allocate VM.Audit VM.Config.CDROM VM.Config.CPU VM.Config.Cloudinit VM.Config.Disk VM.Config.HWType VM.Config.Memory VM.Config.Network VM.Config.Options VM.GuestAgent.Audit VM.PowerMgmt Datastore.Allocate Datastore.AllocateSpace Datastore.AllocateTemplate Datastore.Audit SDN.Audit SDN.Use Sys.AccessNetwork Sys.Audit Sys.Modify","special":0}]`),
		"pvesh get /access/users --output-format json":                      []byte(`[{"comment":"boetticher automation identity","enable":1,"expire":0,"userid":"labadmin@pve"}]`),
		"pvesh get /access/users/'labadmin@pve'/token --output-format json": []byte(`[{"expire":0,"privsep":1,"tokenid":"boetticher"}]`),
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

func TestCheckScopedCredentialReuseRejectsUnexpectedIdentityMetadata(t *testing.T) {
	runner := &fakeRunner{responses: map[string][]byte{
		"pvesh get /access/roles --output-format json":                      []byte(`[{"roleid":"BoetticherProvisioner","privs":"` + ScopedProvisionerPrivileges() + `","special":0}]`),
		"pvesh get /access/users --output-format json":                      []byte(`[{"comment":"operator-owned","enable":1,"expire":0,"userid":"labadmin@pve"}]`),
		"pvesh get /access/users/'labadmin@pve'/token --output-format json": []byte(`[{"expire":0,"privsep":1,"tokenid":"boetticher"}]`),
	}}
	if err := CheckScopedCredentialReuse(context.Background(), runner, "192.0.2.10", "root", "labadmin@pve", "boetticher", "BoetticherProvisioner"); err == nil || !strings.Contains(err.Error(), "unexpected user") {
		t.Fatalf("unexpected scoped credential metadata was accepted: %v", err)
	}
	for _, command := range runner.commands {
		if strings.Contains(command, " create ") || strings.Contains(command, " set ") || strings.Contains(command, " delete ") {
			t.Fatalf("metadata check mutated Proxmox: %s", command)
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
	if _, err := CreateScopedCredentialsWithRole(context.Background(), runner, "192.0.2.10", "root", "labadmin@pve", "boetticher", "BoetticherProvisioner", "node"); err != nil {
		t.Fatal(err)
	}
	var userACL, tokenACL bool
	var rootACL bool
	aclCount := 0
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
		if strings.Contains(command, "pvesh set /access/acl") {
			aclCount++
		}
		if strings.Contains(command, "--path /") {
			rootACL = true
		}
	}
	if !userACL || !tokenACL || rootACL || aclCount != len(scopedProvisionerACLPaths("node"))*2 {
		t.Fatalf("credential bootstrap ACLs incomplete: user=%t token=%t commands=%v", userACL, tokenACL, runner.commands)
	}
}

func TestCreateScopedCredentialsRefusesUnexpectedExistingUser(t *testing.T) {
	runner := &fakeRunner{responses: map[string][]byte{
		"pvesh get /access/roles --output-format json": []byte(`[{"roleid":"BoetticherProvisioner","privs":"` + ScopedProvisionerPrivileges() + `","special":0}]`),
		"pvesh get /access/users --output-format json": []byte(`[{"comment":"operator-owned","enable":1,"expire":0,"userid":"labadmin@pve"}]`),
	}}
	if _, err := CreateScopedCredentialsWithRole(context.Background(), runner, "192.0.2.10", "root", "labadmin@pve", "boetticher", "BoetticherProvisioner", "node"); err == nil || !strings.Contains(err.Error(), "expected Boetticher identity") {
		t.Fatalf("unexpected existing Proxmox user was accepted: %v", err)
	}
	for _, command := range runner.commands {
		if strings.Contains(command, "pvesh create /access/users") || strings.Contains(command, "pvesh set /access/acl") {
			t.Fatalf("unexpected existing user triggered mutation: %s", command)
		}
	}
}

func TestEnsureScopedCredentialACLRepairsBackingUserAndToken(t *testing.T) {
	acls := make([]scopedCredentialACLEntry, 0, len(scopedProvisionerACLPaths("node"))*2)
	for _, subject := range []struct {
		value string
		typ   string
	}{{"labadmin@pve", "user"}, {"labadmin@pve!boetticher", "token"}} {
		for _, path := range scopedProvisionerACLPaths("node") {
			acls = append(acls, scopedCredentialACLEntry{Path: path, Propagate: scopedProvisionerACLPropagate(path), RoleID: "BoetticherProvisioner", Type: subject.typ, UGID: subject.value})
		}
	}
	aclData, err := json.Marshal(acls)
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{responses: map[string][]byte{
		"pvesh get /access/roles --output-format json":                      []byte(`[{"roleid":"BoetticherProvisioner","privs":"` + ScopedProvisionerPrivileges() + `","special":0}]`),
		"pvesh get /access/users --output-format json":                      []byte(`[{"comment":"boetticher automation identity","enable":1,"expire":0,"userid":"labadmin@pve"}]`),
		"pvesh get /access/users/'labadmin@pve'/token --output-format json": []byte(`[{"expire":0,"privsep":1,"tokenid":"boetticher"}]`),
		"pvesh get /access/acl --output-format json":                        aclData,
	}}
	if err := EnsureScopedCredentialACL(context.Background(), runner, "192.0.2.10", "root", "labadmin@pve", "boetticher", "BoetticherProvisioner", "node"); err != nil {
		t.Fatal(err)
	}
	want := []string{"pvesh get /access/roles --output-format json", "pvesh get /access/users --output-format json", "pvesh get /access/users/'labadmin@pve'/token --output-format json", "pvesh get /access/acl --output-format json"}
	for _, path := range scopedProvisionerACLPaths("node") {
		want = append(want, "pvesh set /access/acl --path '"+path+"' --users 'labadmin@pve' --roles 'BoetticherProvisioner' --propagate "+strconv.Itoa(scopedProvisionerACLPropagate(path)))
	}
	for _, path := range scopedProvisionerACLPaths("node") {
		want = append(want, "pvesh set /access/acl --path '"+path+"' --tokens 'labadmin@pve!boetticher' --roles 'BoetticherProvisioner' --propagate "+strconv.Itoa(scopedProvisionerACLPropagate(path)))
	}
	want = append(want, "pvesh get /access/acl --output-format json")
	if !reflect.DeepEqual(runner.commands, want) {
		t.Fatalf("scoped credential ACL repair commands = %#v, want %#v", runner.commands, want)
	}
}

func TestScopedProvisionerACLPathsIncludeStorageCollection(t *testing.T) {
	paths := scopedProvisionerACLPaths("node")
	for _, want := range []string{"/storage", "/storage/local", "/storage/boetticher-thin", "/storage/boetticher-backups"} {
		found := false
		for _, path := range paths {
			if path == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("scoped ACL paths omit %q: %v", want, paths)
		}
	}
}

func TestScopedProvisionerACLPathsIncludeTemporaryNetworkProbeRange(t *testing.T) {
	paths := scopedProvisionerACLPaths("node")
	allowed := make(map[string]bool, len(paths))
	for _, path := range paths {
		allowed[path] = true
	}
	for vmid := 910; vmid <= 919; vmid++ {
		path := "/vms/" + strconv.Itoa(vmid)
		if !allowed[path] {
			t.Fatalf("scoped ACL paths omit temporary network probe VMID %d", vmid)
		}
	}
}

func TestStorageCollectionACLDoesNotPropagate(t *testing.T) {
	if got := scopedProvisionerACLPropagate("/storage"); got != 0 {
		t.Fatalf("storage collection propagation = %d, want 0", got)
	}
	for _, path := range []string{"/storage/local", "/storage/boetticher-thin", "/storage/boetticher-backups"} {
		if got := scopedProvisionerACLPropagate(path); got != 1 {
			t.Fatalf("owned storage %s propagation = %d, want 1", path, got)
		}
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

func TestCreatePulseMonitoringCredentialsRefusesUnexpectedExistingUser(t *testing.T) {
	runner := &fakeRunner{responses: map[string][]byte{
		"pvesh get /access/roles --output-format json": []byte(`[{"roleid":"PVEAuditor","privs":"Datastore.Audit Mapping.Audit Pool.Audit SDN.Audit Sys.Audit VM.Audit VM.GuestAgent.Audit","special":1}]`),
		"pvesh get /access/users --output-format json": []byte(`[{"comment":"unexpected","enable":1,"expire":0,"userid":"pulse-monitor@pve"}]`),
	}}
	if _, err := CreatePulseMonitoringCredentials(context.Background(), runner, "192.0.2.10", "root"); err == nil || !strings.Contains(err.Error(), "ownership") {
		t.Fatalf("unexpected existing Pulse monitoring user was accepted: %v", err)
	}
	for _, command := range runner.commands {
		if strings.Contains(command, "pvesh create /access/users/'pulse-monitor@pve'/token") {
			t.Fatalf("unexpected existing Pulse monitoring user triggered token creation: %s", command)
		}
	}
}

func TestReplacePulseMonitoringCredentialsRemovesOnlyVerifiedOwnedToken(t *testing.T) {
	runner := &stalePulseMonitoringTokenRunner{}
	secret, err := ReplacePulseMonitoringCredentials(context.Background(), runner, "192.0.2.10", "root")
	if err != nil {
		t.Fatal(err)
	}
	if secret != "recreated-monitoring-secret" {
		t.Fatalf("ReplacePulseMonitoringCredentials() = %q", secret)
	}
	if !runner.removed {
		t.Fatal("verified stale Pulse monitoring token was not removed")
	}
	joined := strings.Join(runner.commands, "\n")
	for _, required := range []string{
		"pvesh get /access/acl --output-format json",
		"pvesh delete /access/users/'pulse-monitor@pve'/token/'boetticher-monitoring'",
		"pvesh create /access/users/'pulse-monitor@pve'/token/'boetticher-monitoring' --privsep 1 --output-format json",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("Pulse token replacement is missing %q:\n%s", required, joined)
		}
	}
	if containsString(runner.commands, "pvesh delete /access/users/'pulse-monitor@pve'") {
		t.Fatalf("Pulse token replacement removed the monitoring user:\n%s", joined)
	}
	for _, forbidden := range []string{"pvesh delete /access/roles", "recreated-monitoring-secret"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("Pulse token replacement contains forbidden %q:\n%s", forbidden, joined)
		}
	}
}

func TestReplacePulseMonitoringCredentialsRefusesUnexpectedOwnership(t *testing.T) {
	runner := &fakeRunner{responses: map[string][]byte{
		"pvesh get /access/roles --output-format json":                           []byte(`[{"roleid":"PVEAuditor","privs":"Datastore.Audit Mapping.Audit Pool.Audit SDN.Audit Sys.Audit VM.Audit VM.GuestAgent.Audit","special":1}]`),
		"pvesh get /access/users --output-format json":                           []byte(`[{"comment":"unexpected","enable":1,"expire":0,"userid":"pulse-monitor@pve"}]`),
		"pvesh get /access/users/'pulse-monitor@pve'/token --output-format json": []byte(`[{"expire":0,"privsep":1,"tokenid":"boetticher-monitoring"}]`),
	}}
	if _, err := ReplacePulseMonitoringCredentials(context.Background(), runner, "192.0.2.10", "root"); err == nil || !strings.Contains(err.Error(), "ownership") {
		t.Fatalf("unexpected Pulse monitoring ownership was accepted: %v", err)
	}
	for _, command := range runner.commands {
		if strings.Contains(command, "pvesh delete") {
			t.Fatalf("unexpected Pulse monitoring ownership triggered deletion: %s", command)
		}
	}
}

func TestReplacePulseMonitoringCredentialsCreatesAbsentUser(t *testing.T) {
	runner := &fakeRunner{responses: map[string][]byte{
		"pvesh get /access/roles --output-format json":                                                                  []byte(`[{"roleid":"PVEAuditor","privs":"Datastore.Audit Mapping.Audit Pool.Audit SDN.Audit Sys.Audit VM.Audit VM.GuestAgent.Audit","special":1}]`),
		"pvesh get /access/users --output-format json":                                                                  []byte(`[]`),
		"pvesh create /access/users --userid 'pulse-monitor@pve' --comment 'Pulse API-only monitoring identity'":        []byte(`{}`),
		"pvesh get /access/users/'pulse-monitor@pve'/token --output-format json":                                        []byte(`[]`),
		"pvesh create /access/users/'pulse-monitor@pve'/token/'boetticher-monitoring' --privsep 1 --output-format json": []byte(`{"value":"fresh-monitoring-secret"}`),
	}}
	secret, err := ReplacePulseMonitoringCredentials(context.Background(), runner, "192.0.2.10", "root")
	if err != nil || secret != "fresh-monitoring-secret" {
		t.Fatalf("absent Pulse monitoring user was not created: secret=%q err=%v", secret, err)
	}
	created := false
	for _, command := range runner.commands {
		if strings.Contains(command, "pvesh create /access/users --userid 'pulse-monitor@pve'") {
			created = true
		}
		if strings.Contains(command, "pvesh get /access/users/'pulse-monitor@pve'/token") && !created {
			t.Fatalf("absent Pulse monitoring user queried a token endpoint before creation: %s", command)
		}
	}
	if !created {
		t.Fatal("absent Pulse monitoring user did not trigger exact user creation")
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
	_, err := CreateScopedCredentialsWithRole(context.Background(), runner, "192.0.2.10", "root", "labadmin@pve", "boetticher", "BoetticherProvisioner", "node")
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

func TestConfigureIdentitiesLeavesRootRecoveryUntouched(t *testing.T) {
	runner := &fakeRunner{}
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample operator"
	if err := ConfigureIdentities(context.Background(), runner, "192.0.2.10", "root", key, []string{"10.10.99.1:22", "10.10.10.20:443"}); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"command -v visudo", "deb http://deb.debian.org/debian trixie main", "apt-get -o Dir::Etc::sourcelist=", "install --yes --no-install-recommends sudo", "passwd --lock labadmin", "/home/labadmin/.ssh/authorized_keys", "rm -f /etc/sudoers.d/boetticher-labadmin", "visudo -cf /etc/sudoers", "install -d -m 700 -o lab-jump -g lab-jump /home/lab-jump", "chown lab-jump:lab-jump /home/lab-jump.authorized_keys", "AllowUsers root labadmin lab-jump", "Match User lab-jump"} {
		if !strings.Contains(runner.command, required) {
			t.Fatalf("identity bootstrap missing %q: %s", required, runner.command)
		}
	}
	if strings.Contains(runner.command, "/root/.ssh/authorized_keys") || strings.Contains(runner.command, "grep -qxF '"+key+"' /root") {
		t.Fatalf("durable identity setup modified root recovery authorization: %s", runner.command)
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

func TestInactivateRetainedModuleUsesBoundedGuestServiceContract(t *testing.T) {
	for _, guest := range []struct {
		kind     GuestKind
		module   string
		want     string
		services []string
	}{
		{kind: KindQEMU, module: "tailnet-router", want: "/usr/sbin/qm guest exec 200 -- /bin/sh -c", services: []string{"tailscaled"}},
		{kind: KindLXC, module: "airvpn", want: "/usr/sbin/pct exec 200 -- /bin/sh -c", services: []string{"boetticher-airvpn.service"}},
		{kind: KindLXC, module: "arr", want: "/usr/sbin/pct exec 200 -- /bin/sh -c", services: []string{"sonarr", "radarr", "lidarr", "readarr", "prowlarr", "qbittorrent", "boetticher-arr-peer-firewall", "nginx", "LoadState", "not-found"}},
	} {
		t.Run(string(guest.kind)+"/"+guest.module, func(t *testing.T) {
			runner := &fakeRunner{output: []byte("{\"exitcode\":0,\"exited\":1}")}
			if err := InactivateRetainedModule(context.Background(), runner, "192.0.2.10", "root", guest.kind, 200, guest.module); err != nil {
				t.Fatal(err)
			}
			if runner.user != "root" || !strings.Contains(runner.command, guest.want) || !strings.Contains(runner.command, "systemctl disable --now") {
				t.Fatalf("retained inactivation used unexpected command: %#v", runner)
			}
			for _, service := range guest.services {
				if !strings.Contains(runner.command, service) {
					t.Fatalf("retained %s inactivation omitted service %q: %s", guest.module, service, runner.command)
				}
			}
			for _, forbidden := range []string{"systemctl disable --now '*'", "rm -rf", "sudo", "ssh ", "ansible"} {
				if strings.Contains(runner.command, forbidden) {
					t.Fatalf("retained inactivation contains forbidden %q: %s", forbidden, runner.command)
				}
			}
		})
	}
}

func TestInactivateRetainedModuleRejectsUnknownServiceContract(t *testing.T) {
	err := InactivateRetainedModule(context.Background(), &fakeRunner{}, "192.0.2.10", "root", KindLXC, 200, "unknown")
	if err == nil || !strings.Contains(err.Error(), "no bounded service contract") {
		t.Fatalf("unknown retained module was not rejected: %v", err)
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
		if host {
			if !strings.Contains(runner.command, "AllowUsers root labadmin lab-jump lab-netprobe") {
				t.Fatalf("host cleanup does not verify the persistent AllowUsers state: %s", runner.command)
			}
			for _, required := range []string{"authorized_keys.boetticher-cleanup", "/home/labadmin/.ssh/authorized_keys", "grep -Fvx", "sshd -t"} {
				if !strings.Contains(runner.command, required) {
					t.Fatalf("host cleanup does not remove the exact temporary key: missing %q in %s", required, runner.command)
				}
			}
			for _, forbidden := range []string{"passwd --lock", "sed -i", "systemctl reload"} {
				if strings.Contains(runner.command, forbidden) {
					t.Fatalf("host cleanup changes independent recovery state through %q: %s", forbidden, runner.command)
				}
			}
		} else {
			for _, required := range []string{"grep -Fvx --", "authorized_keys.boetticher-cleanup", "/home/labadmin/.ssh/authorized_keys"} {
				if !strings.Contains(runner.command, required) {
					t.Fatalf("guest cleanup does not remove only the injected key: missing %q in %s", required, runner.command)
				}
			}
		}
		if strings.Contains(runner.command, "passwd --lock root") {
			t.Fatalf("temporary cleanup must never change root password state: %s", runner.command)
		}
	}
	if err := RevokeTemporaryRootAccess(context.Background(), &fakeRunner{}, "192.0.2.10", "labadmin", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample operator", false); err == nil {
		t.Fatal("temporary cleanup accepted a non-root transport")
	}
}

func TestConfigureHeadlessPowerPolicyUsesExplicitUnattendedContract(t *testing.T) {
	runner := &fakeRunner{}
	if err := ConfigureHeadlessPowerPolicy(context.Background(), runner, "192.0.2.10", "root"); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"dir=/etc/systemd/logind.conf.d",
		"file=$dir/90-boetticher-headless.conf",
		"HandleLidSwitch=ignore",
		"HandleLidSwitchExternalPower=ignore",
		"HandleLidSwitchDocked=ignore",
		"HandleSuspendKey=ignore",
		"HandleHibernateKey=ignore",
		"IdleAction=ignore",
		"systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target",
		"systemctl restart systemd-logind",
	} {
		if !strings.Contains(runner.command, required) {
			t.Fatalf("headless power policy missing %q: %s", required, runner.command)
		}
	}
	if strings.Contains(runner.command, "systemctl mask poweroff.target") {
		t.Fatalf("headless power policy must not mask controlled poweroff: %s", runner.command)
	}
}

func TestCheckHeadlessPowerPolicyUsesReadOnlyVerification(t *testing.T) {
	runner := &fakeRunner{}
	if err := CheckHeadlessPowerPolicy(context.Background(), runner, "192.0.2.10", "root"); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"install ", "systemctl mask", "systemctl restart", "mktemp"} {
		if strings.Contains(runner.command, forbidden) {
			t.Fatalf("headless power check mutates the host through %q: %s", forbidden, runner.command)
		}
	}
	for _, required := range []string{"90-boetticher-headless.conf", "systemctl is-enabled", "grep -qxF masked"} {
		if !strings.Contains(runner.command, required) {
			t.Fatalf("headless power check missing %q: %s", required, runner.command)
		}
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
	if len(runner.commands) != 4 || runner.commands[0] != "pvesh get /nodes --output-format json" || runner.commands[1] != "pvesh get /nodes/proxmox/network --output-format json" || runner.commands[2] != "ip -j link show" || runner.commands[3] != "ip -j route show default" {
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
	secret, err := CreateScopedCredentialsWithRole(context.Background(), runner, "192.0.2.10", "dave", "labadmin@pve", "boetticher", "BoetticherProvisioner", "node")
	if err != nil || secret != "opaque-token-secret" {
		t.Fatalf("CreateScopedCredentialsWithRole() = %q, %v", secret, err)
	}
	for _, command := range runner.commands {
		if strings.Contains(command, "pvesh") && !strings.HasPrefix(command, "sudo -n ") {
			t.Fatalf("privileged credential command ran without non-interactive sudo: %q", command)
		}
	}
}
