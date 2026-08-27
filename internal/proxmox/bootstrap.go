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
	"sort"
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

// WaitForQEMUIPv4ViaNeighbor discovers a DHCP-backed temporary guest before
// cloud-init can install qemu-guest-agent. The exact builder MAC is the only
// accepted identity; unrelated HOME neighbors are never returned.
func WaitForQEMUIPv4ViaNeighbor(ctx context.Context, runner CommandRunner, address, user, mac string, attempts int, interval time.Duration) (string, error) {
	if runner == nil || address == "" || user == "" || attempts < 1 {
		return "", errors.New("builder neighbor readiness inputs are invalid")
	}
	parsedMAC, err := net.ParseMAC(mac)
	if err != nil || len(parsedMAC) != 6 {
		return "", errors.New("builder neighbor readiness requires a valid MAC")
	}
	if interval <= 0 {
		interval = time.Second
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		output, runErr := runner.Run(ctx, address, user, "/usr/sbin/ip -4 neigh show dev vmbr0")
		if runErr != nil {
			lastErr = runErr
		} else {
			for _, line := range strings.Split(string(output), "\n") {
				fields := strings.Fields(line)
				if len(fields) < 4 || fields[1] != "lladdr" {
					continue
				}
				candidateIP := net.ParseIP(fields[0]).To4()
				candidateMAC, parseErr := net.ParseMAC(fields[2])
				if candidateIP != nil && parseErr == nil && len(candidateMAC) == 6 && candidateMAC.String() == parsedMAC.String() {
					return candidateIP.String(), nil
				}
			}
			lastErr = errors.New("builder MAC is not present in the Proxmox HOME neighbor table")
		}
		if attempt+1 < attempts {
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return "", fmt.Errorf("builder neighbor readiness cancelled: %w", ctx.Err())
			case <-timer.C:
			}
		}
	}
	return "", fmt.Errorf("HOLD: builder DHCP address was not observed for MAC %s after %d attempts: %w", parsedMAC, attempts, lastErr)
}

type SSHRunner struct {
	Port          int
	KnownHosts    string
	StrictHostKey string
	IdentityFile  string
	ConfigFile    string
	// HostAlias selects a generated SSH configuration host, including its
	// ProxyJump policy. It does not change the network destination.
	HostAlias string
	// HostKeyAlias supplies OpenSSH's canonical host-key identity while the
	// network target remains the supplied address. It is used for bootstrap
	// connections whose address is not resolvable through HOME DNS.
	HostKeyAlias string
}

type SSHPhysicalNetworkDiscovery struct {
	Node      string
	Discovery networkmodel.Discovery
}

// DiscoverPhysicalNetworkViaSSH uses the existing fresh-host trust path before
// a Proxmox API token exists. It executes only fixed read-only pvesh and ip
// operations; no interface name is interpolated into a shell command.
func DiscoverPhysicalNetworkViaSSH(ctx context.Context, runner CommandRunner, address, initialUser, bootstrapAddress, configuredTrunk, selectedTrunk string) (SSHPhysicalNetworkDiscovery, error) {
	if runner == nil {
		return SSHPhysicalNetworkDiscovery{}, errors.New("network discovery runner is required")
	}
	nodeOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, "pvesh get /nodes --output-format json"))
	if err != nil {
		if initialUser != "root" && strings.Contains(strings.ToLower(err.Error()), "sudo") {
			return SSHPhysicalNetworkDiscovery{}, fmt.Errorf("HOLD: initial Proxmox user must be root or have non-interactive sudo for bootstrap discovery: %w", err)
		}
		return SSHPhysicalNetworkDiscovery{}, fmt.Errorf("discover Proxmox nodes: %w", err)
	}
	var nodes []Node
	if err := json.Unmarshal(nodeOutput, &nodes); err != nil {
		var envelope struct {
			Data []Node `json:"data"`
		}
		if envelopeErr := json.Unmarshal(nodeOutput, &envelope); envelopeErr != nil || envelope.Data == nil {
			return SSHPhysicalNetworkDiscovery{}, fmt.Errorf("HOLD: decode Proxmox node listing: %w", err)
		}
		nodes = envelope.Data
	}
	node, err := ResolveSingleNode(nodes)
	if err != nil {
		return SSHPhysicalNetworkDiscovery{}, err
	}
	output, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, "pvesh get /nodes/"+node+"/network --output-format json"))
	if err != nil {
		return SSHPhysicalNetworkDiscovery{}, fmt.Errorf("discover Proxmox physical network for node %s: %w", node, err)
	}
	var interfaces []NetworkInterface
	if err := json.Unmarshal(output, &interfaces); err != nil {
		return SSHPhysicalNetworkDiscovery{}, fmt.Errorf("HOLD: decode Proxmox physical network evidence: %w", err)
	}
	routeOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, "ip -j route show default"))
	if err != nil {
		return SSHPhysicalNetworkDiscovery{}, fmt.Errorf("discover Proxmox default route: %w", err)
	}
	var routes []struct {
		Dev string `json:"dev"`
	}
	if err := json.Unmarshal(routeOutput, &routes); err != nil {
		return SSHPhysicalNetworkDiscovery{}, fmt.Errorf("HOLD: decode Proxmox default-route evidence: %w", err)
	}
	if len(routes) != 1 || routes[0].Dev == "" {
		return SSHPhysicalNetworkDiscovery{}, errors.New("HOLD: upstream interface identity is ambiguous (default route is absent or has multiple entries)")
	}
	discovery, err := AnalyzePhysicalNetworkWithDefaultRoute(interfaces, bootstrapAddress, configuredTrunk, selectedTrunk, routes[0].Dev)
	if err != nil {
		return SSHPhysicalNetworkDiscovery{}, err
	}
	return SSHPhysicalNetworkDiscovery{Node: node, Discovery: discovery}, nil
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
	install := privilegedCommand(user, "install -D -m 0644 /dev/stdin /etc/network/interfaces.d/boetticher-management")
	if _, err := runner.RunWithStdin(ctx, address, user, install, strings.NewReader(managementInterfaceConfig)); err != nil {
		return fmt.Errorf("install Proxmox management interface configuration: %w", err)
	}
	beforeAddress, err := runner.Run(ctx, address, user, privilegedCommand(user, "/usr/sbin/ip -4 -j addr show dev vmbr0"))
	if err != nil {
		return fmt.Errorf("read Proxmox HOME address before management reload: %w", err)
	}
	beforeRoute, err := runner.Run(ctx, address, user, privilegedCommand(user, "/usr/sbin/ip -4 -j route show default"))
	if err != nil {
		return fmt.Errorf("read Proxmox default route before management reload: %w", err)
	}
	if _, err := runner.Run(ctx, address, user, privilegedCommand(user, "/usr/sbin/ifreload -a")); err != nil {
		return fmt.Errorf("apply Proxmox management interface configuration: %w", err)
	}
	afterAddress, err := runner.Run(ctx, address, user, privilegedCommand(user, "/usr/sbin/ip -4 -j addr show dev vmbr0"))
	if err != nil {
		return fmt.Errorf("read Proxmox HOME address after management reload: %w", err)
	}
	if !bytes.Equal(beforeAddress, afterAddress) {
		return errors.New("HOLD: Proxmox HOME address changed while applying the management interface")
	}
	afterRoute, err := runner.Run(ctx, address, user, privilegedCommand(user, "/usr/sbin/ip -4 -j route show default"))
	if err != nil {
		return fmt.Errorf("read Proxmox default route after management reload: %w", err)
	}
	if !bytes.Equal(beforeRoute, afterRoute) {
		return errors.New("HOLD: Proxmox HOME default route changed while applying the management interface")
	}
	mgmtAddress, err := runner.Run(ctx, address, user, privilegedCommand(user, "/usr/sbin/ip -4 addr show dev vmbr1.99"))
	if err != nil {
		return fmt.Errorf("read Proxmox management address: %w", err)
	}
	if !strings.Contains(string(mgmtAddress), "inet 10.10.99.5/24") {
		return errors.New("HOLD: Proxmox vmbr1.99 does not have 10.10.99.5/24")
	}
	internalRoute, err := runner.Run(ctx, address, user, privilegedCommand(user, "/usr/sbin/ip -4 route show 10.10.0.0/16"))
	if err != nil {
		return fmt.Errorf("read Proxmox internal management route: %w", err)
	}
	if !strings.Contains(string(internalRoute), "10.10.0.0/16 via 10.10.99.1 dev vmbr1.99") {
		return errors.New("HOLD: Proxmox internal route does not use 10.10.99.1 via vmbr1.99")
	}
	vlanState, err := runner.Run(ctx, address, user, privilegedCommand(user, "/usr/sbin/ip -d link show dev vmbr1"))
	if err != nil {
		return fmt.Errorf("read Proxmox vmbr1 VLAN state: %w", err)
	}
	if !strings.Contains(string(vlanState), "vlan_filtering 1") && !strings.Contains(string(vlanState), "vlan_filtering on") {
		return errors.New("HOLD: Proxmox vmbr1 is not VLAN-aware after management reload")
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
	if r.HostKeyAlias != "" {
		if !safeNodeID(r.HostKeyAlias) {
			return nil, errors.New("SSH host-key alias is not a safe identifier")
		}
		args = append(args, "-o", "HostKeyAlias="+r.HostKeyAlias)
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
	command := "set -eu; id -u labadmin >/dev/null 2>&1 || useradd --create-home --shell /bin/bash labadmin; passwd --lock labadmin; id -u lab-jump >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin lab-jump; install -d -m 700 /home/labadmin/.ssh /etc/ssh/sshd_config.d; install -m 600 /dev/null /home/labadmin/.ssh/authorized_keys; grep -qxF " + shellQuote(adminPublicKey) + " /home/labadmin/.ssh/authorized_keys || printf '%s\\n' " + shellQuote(adminPublicKey) + " >> /home/labadmin/.ssh/authorized_keys; install -m 600 /dev/null /home/lab-jump.authorized_keys; printf '%s\\n' " + shellQuote(jumpKey) + " > /home/lab-jump.authorized_keys; chown lab-jump:lab-jump /home/lab-jump.authorized_keys; chown -R labadmin:labadmin /home/labadmin/.ssh; cat > /etc/sudoers.d/boetticher-labadmin <<'EOF'\n" + proxmoxLabadminSudoers + "\nEOF\nchmod 0440 /etc/sudoers.d/boetticher-labadmin; cat > /etc/ssh/sshd_config.d/90-boetticher-jump.conf <<'EOF'\nAllowUsers labadmin lab-jump\nMatch User lab-jump\n    AuthorizedKeysFile /home/lab-jump.authorized_keys\n    PermitTTY no\n    X11Forwarding no\n    AllowAgentForwarding no\n    AllowTcpForwarding local\n    PermitOpen " + strings.Join(allowedDestinations, " ") + "\nEOF\nvisudo -cf /etc/sudoers\nsshd -t\nsystemctl reload ssh || systemctl reload sshd"
	_, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, command))
	return err
}

// privilegedCommand keeps root-required bootstrap commands non-interactive.
// Root executes the fixed command directly; every other initial user must
// have passwordless sudo or the operation fails without prompting.
func privilegedCommand(user, command string) string {
	if user == "root" {
		return command
	}
	if !strings.ContainsAny(command, ";\n\r") {
		return "sudo -n " + command
	}
	return "sudo -n sh -c " + shellQuote(command)
}

// proxmoxLabadminSudoers is the key-only host-administration boundary used
// after bootstrap. The list is intentionally command-scoped; it is not an
// unrestricted root shell and it does not grant lab-jump any privilege.
const proxmoxLabadminSudoers = `labadmin ALL=(root) NOPASSWD: /usr/bin/pvesh *, /usr/bin/pvesm *, /usr/sbin/ip *, /usr/sbin/ifreload -a, /usr/bin/install *, /usr/bin/mkdir *, /usr/bin/chown *, /usr/bin/chmod *, /usr/bin/systemctl reload ssh, /usr/bin/systemctl reload sshd, /usr/sbin/sshd -t, /usr/bin/visudo -cf /etc/sudoers, /bin/sh -c * /usr/bin/python3 /tmp/boetticher-ansible/ansible-tmp-*/*`

func CreateScopedCredentials(ctx context.Context, runner CommandRunner, address, initialUser, userID, tokenID string) (string, error) {
	return CreateScopedCredentialsWithRole(ctx, runner, address, initialUser, userID, tokenID, "BoetticherProvisioner")
}

const (
	PulseMonitoringUser        = "pulse-monitor@pve"
	PulseMonitoringToken       = "boetticher-monitoring"
	PulseMonitoringRole        = "PVEAuditor"
	PulseMonitoringStorageRole = "PVEDatastoreAdmin"
	PulseMonitoringStoragePath = "/storage"
)

// CreatePulseMonitoringCredentials creates the API-only identity used by the
// Pulse server. The built-in PVEAuditor role is assigned at the root path. A
// separate PVEDatastoreAdmin ACL is limited to /storage because the selected
// Pulse release uses that path for backup inventory; no VM mutation, guest
// agent, SSH, or root monitoring privilege is granted.
func CreatePulseMonitoringCredentials(ctx context.Context, runner CommandRunner, address, initialUser string) (string, error) {
	if runner == nil || address == "" || initialUser == "" {
		return "", errors.New("Pulse monitoring credential bootstrap inputs are invalid")
	}
	rolesOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, "pvesh get /access/roles --output-format json"))
	if err != nil {
		return "", fmt.Errorf("HOLD: inspect Proxmox monitoring roles: %w", err)
	}
	if err := requireBuiltInRole(rolesOutput, PulseMonitoringRole); err != nil {
		return "", fmt.Errorf("HOLD: Proxmox monitoring role %q is unavailable: %w", PulseMonitoringRole, err)
	}
	if err := requireBuiltInRole(rolesOutput, PulseMonitoringStorageRole); err != nil {
		return "", fmt.Errorf("HOLD: Proxmox backup visibility role %q is unavailable: %w", PulseMonitoringStorageRole, err)
	}
	usersOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, "pvesh get /access/users --output-format json"))
	if err != nil {
		return "", fmt.Errorf("HOLD: inspect Proxmox monitoring user: %w", err)
	}
	users, err := accessIDs(usersOutput, "userid", "id")
	if err != nil {
		return "", fmt.Errorf("HOLD: decode Proxmox monitoring users: %w", err)
	}
	if !users[PulseMonitoringUser] {
		createUser := "pvesh create /access/users --userid " + shellQuote(PulseMonitoringUser) + " --comment 'Pulse API-only monitoring identity'"
		if _, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, createUser)); err != nil {
			return "", fmt.Errorf("create Pulse monitoring user: %w", err)
		}
	}
	tokensPath := "pvesh get /access/users/" + shellQuote(PulseMonitoringUser) + "/token --output-format json"
	tokensOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, tokensPath))
	if err != nil {
		return "", fmt.Errorf("HOLD: inspect Pulse monitoring tokens: %w", err)
	}
	tokens, err := accessIDs(tokensOutput, "tokenid", "id")
	if err != nil {
		return "", fmt.Errorf("HOLD: decode Pulse monitoring tokens: %w", err)
	}
	if tokens[PulseMonitoringToken] {
		return "", errors.New("the Pulse monitoring Proxmox token already exists; use its encrypted value or remove it through the approved lifecycle")
	}
	createToken := "pvesh create /access/users/" + shellQuote(PulseMonitoringUser) + "/token/" + shellQuote(PulseMonitoringToken) + " --privsep 1 --output-format json"
	output, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, createToken))
	if err != nil {
		return "", fmt.Errorf("create Pulse monitoring token: %w", err)
	}
	var response struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(output, &response); err != nil {
		return "", fmt.Errorf("decode Pulse monitoring token response: %w", err)
	}
	if response.Value == "" {
		return "", errors.New("Pulse monitoring token response did not contain a secret")
	}
	tokenIdentity := PulseMonitoringUser + "!" + PulseMonitoringToken
	for _, acl := range []struct {
		path string
		role string
	}{
		{path: "/", role: PulseMonitoringRole},
		{path: PulseMonitoringStoragePath, role: PulseMonitoringStorageRole},
	} {
		for _, subject := range []struct {
			flag  string
			value string
		}{
			{flag: "--users", value: PulseMonitoringUser},
			{flag: "--tokens", value: tokenIdentity},
		} {
			setACL := "pvesh set /access/acl --path " + shellQuote(acl.path) + " " + subject.flag + " " + shellQuote(subject.value) + " --roles " + shellQuote(acl.role) + " --propagate 1"
			if _, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, setACL)); err != nil {
				return "", fmt.Errorf("assign Pulse monitoring role %q at %s: %w", acl.role, acl.path, err)
			}
		}
	}
	return response.Value, nil
}

func requireBuiltInRole(output []byte, wanted string) error {
	var document any
	if err := json.Unmarshal(output, &document); err != nil {
		return fmt.Errorf("decode role listing: %w", err)
	}
	entries, err := roleEntries(document)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.RoleID != wanted {
			continue
		}
		if roleHasSpecialPrivileges(entry.Special) {
			return errors.New("role has special privileges")
		}
		return nil
	}
	return errors.New("role is not present")
}

func CreateScopedCredentialsWithRole(ctx context.Context, runner CommandRunner, address, initialUser, userID, tokenID, role string) (string, error) {
	if !safeID(userID) || !safeID(tokenID) || !safeID(role) {
		return "", errors.New("Proxmox identity and token IDs must be simple identifiers")
	}
	privileges := ScopedProvisionerPrivileges()
	roleOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, "pvesh get /access/roles --output-format json"))
	if err != nil {
		return "", fmt.Errorf("HOLD: inspect Proxmox role %q: %w", role, err)
	}
	exists, err := validateScopedRoleJSON(roleOutput, role, privileges)
	if err != nil {
		return "", fmt.Errorf("HOLD: Proxmox role %q is not the expected bounded role: %w", role, err)
	}
	if !exists {
		createRole := "pvesh create /access/roles --roleid " + shellQuote(role) + " --privs " + shellQuote(privileges)
		if _, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, createRole)); err != nil {
			return "", fmt.Errorf("create bounded Proxmox role %q: %w", role, err)
		}
	}
	usersOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, "pvesh get /access/users --output-format json"))
	if err != nil {
		return "", fmt.Errorf("HOLD: inspect Proxmox users: %w", err)
	}
	users, err := accessIDs(usersOutput, "userid", "id")
	if err != nil {
		return "", fmt.Errorf("HOLD: decode Proxmox users: %w", err)
	}
	if !users[userID] {
		createUser := "pvesh create /access/users --userid " + shellQuote(userID) + " --comment 'boetticher automation identity'"
		if _, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, createUser)); err != nil {
			return "", fmt.Errorf("create Proxmox automation user: %w", err)
		}
	}
	tokensOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, "pvesh get /access/users/"+shellQuote(userID)+"/token --output-format json"))
	if err != nil {
		return "", fmt.Errorf("HOLD: inspect Proxmox tokens for %s: %w", userID, err)
	}
	tokens, err := accessIDs(tokensOutput, "tokenid", "id")
	if err != nil {
		return "", fmt.Errorf("HOLD: decode Proxmox tokens: %w", err)
	}
	if tokens[tokenID] {
		return "", errors.New("the requested Proxmox token already exists; use a new token ID or existing encrypted credentials")
	}
	createToken := "pvesh create /access/users/" + shellQuote(userID) + "/token/" + shellQuote(tokenID) + " --privsep 1 --output-format json"
	output, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, createToken))
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
	setTokenACL := "pvesh set /access/acl --path / --tokens " + shellQuote(userID+"!"+tokenID) + " --roles " + shellQuote(role) + " --propagate 1"
	if _, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, setTokenACL)); err != nil {
		return "", fmt.Errorf("assign bounded Proxmox role to token: %w", err)
	}
	return response.Value, nil
}

// accessIDs decodes the small JSON listings returned by pvesh for users and
// tokens. Listing first is intentional: a failed lookup must remain a HOLD,
// rather than being interpreted as permission or transport failure and
// followed by an unauthorized create operation.
func accessIDs(output []byte, fields ...string) (map[string]bool, error) {
	var document any
	if err := json.Unmarshal(output, &document); err != nil {
		return nil, err
	}
	for {
		object, ok := document.(map[string]any)
		if !ok {
			break
		}
		data, exists := object["data"]
		if !exists {
			break
		}
		document = data
	}
	result := make(map[string]bool)
	add := func(object map[string]any) {
		for _, field := range fields {
			if value, ok := object[field].(string); ok && value != "" {
				result[value] = true
				return
			}
		}
	}
	switch value := document.(type) {
	case []any:
		for _, item := range value {
			object, ok := item.(map[string]any)
			if !ok {
				return nil, errors.New("access listing contains a non-object entry")
			}
			add(object)
		}
	case map[string]any:
		add(value)
		if len(result) == 0 {
			for key, item := range value {
				if _, ok := item.(map[string]any); ok {
					result[key] = true
				}
			}
		}
	default:
		return nil, errors.New("access listing must be a JSON object or array")
	}
	return result, nil
}

// validateScopedRoleJSON validates the exact privilege boundary returned by
// the Proxmox role listing endpoint. Role lookup is deliberately performed
// separately from role creation so an API/permission failure cannot be
// mistaken for an absent role and silently trigger a mutation.
func validateScopedRoleJSON(output []byte, wantedRole, wantedPrivileges string) (bool, error) {
	var document any
	if err := json.Unmarshal(output, &document); err != nil {
		return false, fmt.Errorf("decode role listing: %w", err)
	}
	entries, err := roleEntries(document)
	if err != nil {
		return false, err
	}
	wanted := canonicalPrivileges(wantedPrivileges)
	for _, entry := range entries {
		if entry.RoleID != wantedRole {
			continue
		}
		if roleHasSpecialPrivileges(entry.Special) {
			return true, errors.New("role has special privileges")
		}
		if canonicalPrivileges(entry.Privileges) != wanted {
			return true, fmt.Errorf("privileges %q do not match required set %q", entry.Privileges, wantedPrivileges)
		}
		return true, nil
	}
	return false, nil
}

type proxmoxRoleEntry struct {
	RoleID     string
	Privileges string
	Special    any
}

func roleEntries(document any) ([]proxmoxRoleEntry, error) {
	if object, ok := document.(map[string]any); ok {
		if data, exists := object["data"]; exists {
			return roleEntries(data)
		}
		if _, hasRoleID := object["roleid"]; hasRoleID {
			return []proxmoxRoleEntry{roleEntryFromObject(object, "")}, nil
		}
		if _, hasPrivileges := object["privs"]; hasPrivileges {
			return []proxmoxRoleEntry{roleEntryFromObject(object, "")}, nil
		}
		entries := make([]proxmoxRoleEntry, 0, len(object))
		for roleID, value := range object {
			roleObject, ok := value.(map[string]any)
			if !ok {
				continue
			}
			entries = append(entries, roleEntryFromObject(roleObject, roleID))
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].RoleID < entries[j].RoleID })
		return entries, nil
	}
	if array, ok := document.([]any); ok {
		entries := make([]proxmoxRoleEntry, 0, len(array))
		for _, value := range array {
			object, ok := value.(map[string]any)
			if !ok {
				return nil, errors.New("role listing contains a non-object entry")
			}
			entries = append(entries, roleEntryFromObject(object, ""))
		}
		return entries, nil
	}
	return nil, errors.New("role listing must be a JSON object or array")
}

func roleEntryFromObject(object map[string]any, fallbackRoleID string) proxmoxRoleEntry {
	roleID, _ := object["roleid"].(string)
	if roleID == "" {
		roleID = fallbackRoleID
	}
	privileges, _ := object["privs"].(string)
	return proxmoxRoleEntry{RoleID: roleID, Privileges: privileges, Special: object["special"]}
}

func roleHasSpecialPrivileges(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case float64:
		return typed != 0
	case string:
		return typed != "" && typed != "0" && !strings.EqualFold(typed, "false")
	default:
		return value != nil
	}
}

func canonicalPrivileges(value string) string {
	fields := strings.Fields(strings.ReplaceAll(value, ",", " "))
	sort.Strings(fields)
	return strings.Join(fields, " ")
}

// ScopedProvisionerPrivileges is the complete privilege set required by the
// currently implemented artifact, guest, storage, guest-agent, and pinned
// image-download paths. Keep this explicit so a new API operation requires a
// deliberate privilege review rather than silently broadening the role.
func ScopedProvisionerPrivileges() string {
	return "VM.Allocate VM.Audit VM.Config.CDROM VM.Config.CPU VM.Config.Cloudinit VM.Config.Disk VM.Config.HWType VM.Config.Memory VM.Config.Network VM.Config.Options VM.GuestAgent.Audit VM.PowerMgmt Datastore.Allocate Datastore.AllocateSpace Datastore.AllocateTemplate Datastore.Audit SDN.Audit SDN.Use Sys.AccessNetwork Sys.Audit Sys.Modify"
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
