package proxmox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	networkmodel "github.com/gofastercloud/boetticher/internal/network"
)

type CommandRunner interface {
	Run(ctx context.Context, address, user, command string) ([]byte, error)
}

// StreamCommandRunner exposes remote stdout without materialising it in a
// byte slice. It is used for artifact-sized builder output.
type StreamCommandRunner interface {
	RunStream(ctx context.Context, address, user, command string, stdout io.Writer) error
	RunArgsStream(ctx context.Context, address, user string, commandArgs []string, stdout io.Writer) error
}

// CheckBuilderCapacity verifies the disposable builder has enough free space
// for the full appliance construction before any build work starts.
func CheckBuilderCapacity(ctx context.Context, runner CommandRunner, address, user string, minimumFreeGiB int) error {
	if runner == nil || minimumFreeGiB <= 0 {
		return errors.New("builder capacity check requires a runner and positive minimum")
	}
	output, err := runner.Run(ctx, address, user, "df -Pk /")
	if err != nil {
		return fmt.Errorf("inspect temporary builder capacity: %w", err)
	}
	availableKiB, err := parseAvailableKiB(output)
	if err != nil {
		return fmt.Errorf("inspect temporary builder capacity: %w", err)
	}
	wantedKiB := int64(minimumFreeGiB) * 1024 * 1024
	if availableKiB < wantedKiB {
		return fmt.Errorf("HOLD: temporary builder has %d GiB free, need at least %d GiB", availableKiB/(1024*1024), minimumFreeGiB)
	}
	return nil
}

func parseAvailableKiB(output []byte) (int64, error) {
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] == "Filesystem" {
			continue
		}
		available, err := strconv.ParseInt(fields[3], 10, 64)
		if err == nil && available >= 0 {
			return available, nil
		}
	}
	return 0, errors.New("df output did not contain a valid available-space value")
}

// ArgsCommandRunner executes a fixed remote executable with separate
// arguments. Callers use this for untrusted-but-validated read filters so the
// transport never has to assemble a shell command.
type ArgsCommandRunner interface {
	RunArgs(ctx context.Context, address, user string, args []string) ([]byte, error)
}

type StdinCommandRunner interface {
	CommandRunner
	RunWithStdin(context.Context, string, string, string, io.Reader) ([]byte, error)
}

// WaitForSSH is a bounded readiness gate used after an appliance is started.
// Guest creation is not treated as reachability proof: an authenticated
// command through the configured SSH path must succeed before deployment
// continues. The runner owns the transport, including ProxyJump, so this
// works for internal guests that are reachable only through the bastion.
func WaitForSSH(ctx context.Context, runner CommandRunner, address, user string, attempts int, interval time.Duration) error {
	if runner == nil {
		return errors.New("SSH readiness runner is required")
	}
	if net.ParseIP(address) == nil || user == "" || attempts < 1 {
		return errors.New("SSH readiness identity is invalid")
	}
	if interval <= 0 {
		interval = time.Second
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("SSH readiness cancelled for %s: %w", address, err)
		}
		_, err := runner.Run(ctx, address, user, "true")
		if err == nil {
			return nil
		}
		lastErr = err
		if attempt+1 < attempts {
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return fmt.Errorf("SSH readiness cancelled for %s: %w", address, ctx.Err())
			case <-timer.C:
			}
		}
	}
	return fmt.Errorf("HOLD: SSH readiness failed for %s@%s after %d attempts: %w", user, address, attempts, lastErr)
}

// WaitForCommand is a bounded post-SSH readiness gate for infrastructure
// helpers whose files and packages are installed by first boot. It uses the
// same authenticated transport as WaitForSSH and accepts only a fixed command
// supplied by Core.
func WaitForCommand(ctx context.Context, runner CommandRunner, address, user, command string, attempts int, interval time.Duration) error {
	if runner == nil {
		return errors.New("command readiness runner is required")
	}
	if net.ParseIP(address) == nil || user == "" || command == "" || attempts < 1 {
		return errors.New("command readiness identity is invalid")
	}
	if interval <= 0 {
		interval = time.Second
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("command readiness cancelled for %s: %w", address, err)
		}
		if _, err := runner.Run(ctx, address, user, command); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if attempt+1 < attempts {
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return fmt.Errorf("command readiness cancelled for %s: %w", address, ctx.Err())
			case <-timer.C:
			}
		}
	}
	return fmt.Errorf("HOLD: command readiness failed for %s@%s after %d attempts: %w", user, address, attempts, lastErr)
}

type SSHRunner struct {
	Port          int
	KnownHosts    string
	StrictHostKey string
	IdentityFile  string
	ConfigFile    string
	HostAlias     string
}

// DiscoverPhysicalNetworkViaSSH uses the existing fresh-host trust path before
// a Proxmox API token exists. It executes only fixed read-only pvesh and ip
// operations; no interface name is interpolated into a shell command.
func DiscoverPhysicalNetworkViaSSH(ctx context.Context, runner CommandRunner, address, initialUser, node, bootstrapAddress, configuredTrunk, selectedTrunk string) (networkmodel.Discovery, error) {
	if runner == nil {
		return networkmodel.Discovery{}, errors.New("network discovery runner is required")
	}
	if !safeID(node) {
		return networkmodel.Discovery{}, errors.New("Proxmox node is not a safe identifier")
	}
	output, err := runner.Run(ctx, address, initialUser, "pvesh get /nodes/"+node+"/network --output-format json")
	if err != nil {
		return networkmodel.Discovery{}, fmt.Errorf("discover Proxmox physical network: %w", err)
	}
	var interfaces []NetworkInterface
	if err := json.Unmarshal(output, &interfaces); err != nil {
		return networkmodel.Discovery{}, fmt.Errorf("decode Proxmox physical network evidence: %w", err)
	}
	routeOutput, err := runner.Run(ctx, address, initialUser, "ip -j route show default")
	if err != nil {
		return networkmodel.Discovery{}, fmt.Errorf("discover Proxmox default route: %w", err)
	}
	var routes []struct {
		Dev string `json:"dev"`
	}
	if err := json.Unmarshal(routeOutput, &routes); err != nil {
		return networkmodel.Discovery{}, fmt.Errorf("decode Proxmox default-route evidence: %w", err)
	}
	if len(routes) != 1 || routes[0].Dev == "" {
		return networkmodel.Discovery{}, errors.New("HOLD: upstream interface identity is ambiguous (default route is absent or has multiple entries)")
	}
	return AnalyzePhysicalNetworkWithDefaultRoute(interfaces, bootstrapAddress, configuredTrunk, selectedTrunk, routes[0].Dev)
}

func (r SSHRunner) Run(ctx context.Context, address, user, command string) ([]byte, error) {
	return r.runArgs(ctx, address, user, []string{command}, os.Stdin)
}

// RunArgs executes one fixed remote executable and its arguments. OpenSSH
// receives the executable and arguments separately; no local shell fragment
// is constructed from caller input.
func (r SSHRunner) RunArgs(ctx context.Context, address, user string, commandArgs []string) ([]byte, error) {
	return r.runArgs(ctx, address, user, commandArgs, os.Stdin)
}

// RunWithStdin executes one validated remote command while streaming the
// caller-supplied value over SSH stdin. It is used for secrets so plaintext
// never enters the command line or a persistent variable document.
func (r SSHRunner) RunWithStdin(ctx context.Context, address, user, command string, stdin io.Reader) ([]byte, error) {
	if stdin == nil {
		return nil, errors.New("SSH stdin is required")
	}
	return r.runArgs(ctx, address, user, []string{command}, stdin)
}

// RunStream executes a fixed remote command and writes stdout directly to the
// supplied destination. SSH stderr is bounded so a failed remote process
// cannot create an unbounded controller-side diagnostic buffer.
func (r SSHRunner) RunStream(ctx context.Context, address, user, command string, stdout io.Writer) error {
	if stdout == nil {
		return errors.New("SSH stdout destination is required")
	}
	return r.runArgsStream(ctx, address, user, []string{command}, os.Stdin, stdout)
}

// RunArgsStream is the argument-preserving streaming form of RunArgs.
func (r SSHRunner) RunArgsStream(ctx context.Context, address, user string, commandArgs []string, stdout io.Writer) error {
	if stdout == nil {
		return errors.New("SSH stdout destination is required")
	}
	return r.runArgsStream(ctx, address, user, commandArgs, os.Stdin, stdout)
}

const managementInterfaceConfig = `auto vmbr1.99
iface vmbr1.99 inet static
    address 10.10.99.5/24
    vlan-raw-device vmbr1
    up ip route replace 10.10.0.0/16 via 10.10.99.1 dev vmbr1.99
    down ip route del 10.10.0.0/16 via 10.10.99.1 dev vmbr1.99 || true
`

// ConfigureManagementNetwork establishes the fixed virtual-only Proxmox
// management leg. It never changes vmbr0, its member, or the default route.
func ConfigureManagementNetwork(ctx context.Context, runner StdinCommandRunner, address, user string) error {
	if runner == nil {
		return errors.New("management network runner is required")
	}
	install := "sudo -n install -D -m 0644 /dev/stdin /etc/network/interfaces.d/boetticher-management"
	if _, err := runner.RunWithStdin(ctx, address, user, install, strings.NewReader(managementInterfaceConfig)); err != nil {
		return fmt.Errorf("install Proxmox management interface configuration: %w", err)
	}
	verify := `sudo -n sh -c 'set -eu
before_vmbr0_addr=$(ip -4 -j addr show dev vmbr0)
before_default_route=$(ip -4 -j route show default)
ifreload -a
test "$(ip -4 -j addr show dev vmbr0)" = "$before_vmbr0_addr"
test "$(ip -4 -j route show default)" = "$before_default_route"
ip -4 addr show dev vmbr1.99 | grep -Fq "inet 10.10.99.5/24"
ip -4 route show 10.10.0.0/16 | grep -Fq "10.10.0.0/16 via 10.10.99.1 dev vmbr1.99"
ip -d link show dev vmbr1 | grep -Eq "vlan_filtering (1|on)"
'`
	if _, err := runner.Run(ctx, address, user, verify); err != nil {
		return fmt.Errorf("apply and verify Proxmox management interface configuration: %w", err)
	}
	return nil
}

func (r SSHRunner) runArgs(ctx context.Context, address, user string, commandArgs []string, stdin io.Reader) ([]byte, error) {
	var output bytes.Buffer
	if err := r.runArgsStream(ctx, address, user, commandArgs, stdin, &output); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func (r SSHRunner) runArgsStream(ctx context.Context, address, user string, commandArgs []string, stdin io.Reader, stdout io.Writer) error {
	args, err := r.commandArgs(address, user, commandArgs)
	if err != nil {
		return err
	}
	process := exec.CommandContext(ctx, "ssh", args...)
	process.Stdin = stdin
	process.Stdout = stdout
	stderr := &boundedOutput{limit: 64 << 10}
	process.Stderr = stderr
	err = process.Run()
	if err != nil {
		message := strings.TrimSpace(stderr.String())
		if message != "" {
			return fmt.Errorf("SSH bootstrap command failed: %w: %s", err, message)
		}
		return fmt.Errorf("SSH bootstrap command failed: %w", err)
	}
	return nil
}

type boundedOutput struct {
	buf   bytes.Buffer
	limit int
}

func (b *boundedOutput) Write(data []byte) (int, error) {
	remaining := b.limit - b.buf.Len()
	if remaining > 0 {
		if len(data) > remaining {
			_, _ = b.buf.Write(data[:remaining])
		} else {
			_, _ = b.buf.Write(data)
		}
	}
	return len(data), nil
}

func (b *boundedOutput) String() string {
	return b.buf.String()
}

func (r SSHRunner) commandArgs(address, user string, commandArgs []string) ([]string, error) {
	if net.ParseIP(address) == nil {
		return nil, fmt.Errorf("Proxmox bootstrap address must be an IP address")
	}
	if user == "" {
		return nil, errors.New("bootstrap SSH user is required")
	}
	if len(commandArgs) == 0 || commandArgs[0] == "" {
		return nil, errors.New("SSH remote command is required")
	}
	args := []string{"-o", "BatchMode=no", "-o", "ForwardAgent=no", "-o", "ForwardX11=no"}
	strictHostKey := r.StrictHostKey
	if strictHostKey == "" {
		strictHostKey = "ask"
	}
	args = append(args, "-o", "StrictHostKeyChecking="+strictHostKey)
	if r.KnownHosts != "" {
		args = append(args, "-o", "UserKnownHostsFile="+r.KnownHosts)
	}
	if r.ConfigFile != "" {
		args = append(args, "-F", r.ConfigFile)
	}
	if r.Port != 0 {
		args = append(args, "-p", fmt.Sprint(r.Port))
	}
	if r.IdentityFile != "" {
		args = append(args, "-i", r.IdentityFile)
	}
	target := address
	if r.HostAlias != "" {
		if !safeID(r.HostAlias) {
			return nil, errors.New("SSH host alias is not a safe identifier")
		}
		target = r.HostAlias
	}
	args = append(args, user+"@"+target)
	args = append(args, commandArgs...)
	return args, nil
}

func InstallOperatorKey(ctx context.Context, runner CommandRunner, address, initialUser, publicKey string) error {
	if err := validatePublicKey(publicKey); err != nil {
		return err
	}
	command := "umask 077; install -d -m 700 ~/.ssh; touch ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys; grep -qxF " + shellQuote(publicKey) + " ~/.ssh/authorized_keys || printf '%s\\n' " + shellQuote(publicKey) + " >> ~/.ssh/authorized_keys"
	_, err := runner.Run(ctx, address, initialUser, command)
	return err
}

func ConfigureIdentities(ctx context.Context, runner CommandRunner, address, initialUser, adminPublicKey string, allowedDestinations []string) error {
	if err := validatePublicKey(adminPublicKey); err != nil {
		return err
	}
	if len(allowedDestinations) == 0 {
		return errors.New("at least one bastion destination is required")
	}
	for _, destination := range allowedDestinations {
		if !strings.Contains(destination, ":22") || strings.ContainsAny(destination, "'\n\r") {
			return fmt.Errorf("invalid bastion destination %q", destination)
		}
	}
	// Public keys and destination addresses are the only values interpolated;
	// credentials are never placed in this command.
	jumpKey := "restrict,port-forwarding,permitopen=\"" + strings.Join(allowedDestinations, "\",permitopen=\"") + "\" " + publicKeyLine(adminPublicKey)
	command := "set -eu; id -u labadmin >/dev/null 2>&1 || useradd --create-home --shell /bin/bash labadmin; passwd --lock labadmin; id -u lab-jump >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin lab-jump; install -d -m 700 /home/labadmin/.ssh /etc/ssh/sshd_config.d; install -m 600 /dev/null /home/labadmin/.ssh/authorized_keys; grep -qxF " + shellQuote(adminPublicKey) + " /home/labadmin/.ssh/authorized_keys || printf '%s\\n' " + shellQuote(adminPublicKey) + " >> /home/labadmin/.ssh/authorized_keys; install -m 600 /dev/null /home/lab-jump.authorized_keys; printf '%s\\n' " + shellQuote(jumpKey) + " > /home/lab-jump.authorized_keys; chown -R labadmin:labadmin /home/labadmin/.ssh; cat > /etc/sudoers.d/boetticher-labadmin <<'EOF'\n" + proxmoxLabadminSudoers + "\nEOF\nchmod 0440 /etc/sudoers.d/boetticher-labadmin; cat > /etc/ssh/sshd_config.d/90-boetticher-jump.conf <<'EOF'\nMatch User lab-jump\n    AuthorizedKeysFile /home/lab-jump.authorized_keys\n    PermitTTY no\n    X11Forwarding no\n    AllowAgentForwarding no\n    AllowTcpForwarding local\n    PermitOpen " + strings.Join(allowedDestinations, " ") + "\nEOF\nvisudo -cf /etc/sudoers\nsshd -t\nsystemctl reload ssh || systemctl reload sshd"
	_, err := runner.Run(ctx, address, initialUser, command)
	return err
}

// proxmoxLabadminSudoers is the key-only host-administration boundary used
// after bootstrap. The list is intentionally command-scoped; it is not an
// unrestricted root shell and it does not grant lab-jump any privilege.
const proxmoxLabadminSudoers = `labadmin ALL=(root) NOPASSWD: /usr/bin/pvesh *, /usr/bin/pvesm *, /usr/sbin/ip *, /usr/sbin/ifreload -a, /usr/bin/install *, /usr/bin/mkdir *, /usr/bin/chown *, /usr/bin/chmod *, /usr/bin/systemctl reload ssh, /usr/bin/systemctl reload sshd, /usr/sbin/sshd -t, /usr/bin/visudo -cf /etc/sudoers`

func CreateScopedCredentials(ctx context.Context, runner CommandRunner, address, initialUser, userID, tokenID string) (string, error) {
	return CreateScopedCredentialsWithRole(ctx, runner, address, initialUser, userID, tokenID, "BoetticherProvisioner")
}

func CreateScopedCredentialsWithRole(ctx context.Context, runner CommandRunner, address, initialUser, userID, tokenID, role string) (string, error) {
	if !safeID(userID) || !safeID(tokenID) || !safeID(role) {
		return "", errors.New("Proxmox identity and token IDs must be simple identifiers")
	}
	privileges := ScopedProvisionerPrivileges()
	command := "set -eu; pvesh get /access/roles/" + shellQuote(role) + " >/dev/null 2>&1 || pvesh create /access/roles/" + shellQuote(role) + " --privs " + shellQuote(privileges) + " >/dev/null; pvesh get /access/users/" + shellQuote(userID) + " >/dev/null 2>&1 || pvesh create /access/users --userid " + shellQuote(userID) + " --comment 'boetticher automation identity' >/dev/null; if pvesh get /access/users/" + shellQuote(userID) + "/token/" + shellQuote(tokenID) + " >/dev/null 2>&1; then echo 'the requested Proxmox token already exists; use a new token ID or existing encrypted credentials' >&2; exit 23; fi; pvesh create /access/acl --path / --users " + shellQuote(userID) + " --roles " + shellQuote(role) + " --propagate 1 >/dev/null; pvesh create /access/users/" + shellQuote(userID) + "/token/" + shellQuote(tokenID) + " --privsep 1 --output-format json"
	output, err := runner.Run(ctx, address, initialUser, command)
	if err != nil {
		return "", err
	}
	var response struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(output, &response); err != nil {
		return "", fmt.Errorf("decode Proxmox token response: %w", err)
	}
	if response.Value == "" {
		return "", errors.New("Proxmox token response did not contain a secret")
	}
	return response.Value, nil
}

// ScopedProvisionerPrivileges is the complete privilege set required by the
// currently implemented artifact, guest, storage, guest-agent, and pinned
// image-download paths. Keep this explicit so a new API operation requires a
// deliberate privilege review rather than silently broadening the role.
func ScopedProvisionerPrivileges() string {
	return "VM.Allocate VM.Audit VM.Config.CDROM VM.Config.CPU VM.Config.Cloudinit VM.Config.Disk VM.Config.HWType VM.Config.Memory VM.Config.MountPoint VM.Config.Network VM.Config.Options VM.Console VM.GuestAgent.Audit VM.PowerMgmt Datastore.AllocateSpace Datastore.AllocateTemplate Datastore.Audit Sys.AccessNetwork Sys.Audit"
}

func ValidatePublicKey(publicKey string) error {
	if strings.TrimSpace(publicKey) == "" || strings.ContainsAny(publicKey, "\r\n'") || !strings.Contains(publicKey, " ") {
		return errors.New("operator SSH public key must be a single OpenSSH public-key line")
	}
	return nil
}

func validatePublicKey(publicKey string) error { return ValidatePublicKey(publicKey) }

func publicKeyLine(publicKey string) string { return publicKey }

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func safeID(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !(r == '@' || r == '!' || r == '.' || r == '_' || r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
