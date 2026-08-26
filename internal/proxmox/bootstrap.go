package proxmox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"

	networkmodel "github.com/gofastercloud/boetticher/internal/network"
)

type CommandRunner interface {
	Run(ctx context.Context, address, user, command string) ([]byte, error)
}

type StdinCommandRunner interface {
	CommandRunner
	RunWithStdin(context.Context, string, string, string, io.Reader) ([]byte, error)
}

type SSHRunner struct {
	Port          int
	KnownHosts    string
	StrictHostKey string
	IdentityFile  string
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
	return r.run(ctx, address, user, command, os.Stdin)
}

// RunWithStdin executes one validated remote command while streaming the
// caller-supplied value over SSH stdin. It is used for secrets so plaintext
// never enters the command line or a persistent variable document.
func (r SSHRunner) RunWithStdin(ctx context.Context, address, user, command string, stdin io.Reader) ([]byte, error) {
	if stdin == nil {
		return nil, errors.New("SSH stdin is required")
	}
	return r.run(ctx, address, user, command, stdin)
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
	if _, err := runner.Run(ctx, address, user, "sudo -n ifreload -a && ip -4 addr show dev vmbr1.99 && ip -4 route show 10.10.0.0/16"); err != nil {
		return fmt.Errorf("apply and verify Proxmox management interface configuration: %w", err)
	}
	return nil
}

func (r SSHRunner) run(ctx context.Context, address, user, command string, stdin io.Reader) ([]byte, error) {
	if net.ParseIP(address) == nil {
		return nil, fmt.Errorf("Proxmox bootstrap address must be an IP address")
	}
	if user == "" {
		return nil, errors.New("bootstrap SSH user is required")
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
	if r.Port != 0 {
		args = append(args, "-p", fmt.Sprint(r.Port))
	}
	if r.IdentityFile != "" {
		args = append(args, "-i", r.IdentityFile)
	}
	args = append(args, user+"@"+address, command)
	process := exec.CommandContext(ctx, "ssh", args...)
	process.Stdin = stdin
	output, err := process.Output()
	if err != nil {
		return nil, fmt.Errorf("SSH bootstrap command failed: %w", err)
	}
	return output, nil
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
	command := "set -eu; id -u labadmin >/dev/null 2>&1 || useradd --create-home --shell /bin/bash labadmin; id -u lab-jump >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin lab-jump; install -d -m 700 /home/labadmin/.ssh /etc/ssh/sshd_config.d; install -m 600 /dev/null /home/labadmin/.ssh/authorized_keys; grep -qxF " + shellQuote(adminPublicKey) + " /home/labadmin/.ssh/authorized_keys || printf '%s\\n' " + shellQuote(adminPublicKey) + " >> /home/labadmin/.ssh/authorized_keys; install -m 600 /dev/null /home/lab-jump.authorized_keys; printf '%s\\n' " + shellQuote(jumpKey) + " > /home/lab-jump.authorized_keys; chown -R labadmin:labadmin /home/labadmin/.ssh; cat > /etc/ssh/sshd_config.d/90-boetticher-jump.conf <<'EOF'\nMatch User lab-jump\n    AuthorizedKeysFile /home/lab-jump.authorized_keys\n    PermitTTY no\n    X11Forwarding no\n    AllowAgentForwarding no\n    AllowTcpForwarding local\n    PermitOpen " + strings.Join(allowedDestinations, " ") + "\nEOF\nsshd -t\nsystemctl reload ssh || systemctl reload sshd"
	_, err := runner.Run(ctx, address, initialUser, command)
	return err
}

func CreateScopedCredentials(ctx context.Context, runner CommandRunner, address, initialUser, userID, tokenID string) (string, error) {
	return CreateScopedCredentialsWithRole(ctx, runner, address, initialUser, userID, tokenID, "BoetticherProvisioner")
}

func CreateScopedCredentialsWithRole(ctx context.Context, runner CommandRunner, address, initialUser, userID, tokenID, role string) (string, error) {
	if !safeID(userID) || !safeID(tokenID) || !safeID(role) {
		return "", errors.New("Proxmox identity and token IDs must be simple identifiers")
	}
	privileges := "VM.Allocate VM.Audit VM.Config.CDROM VM.Config.CPU VM.Config.Disk VM.Config.HWType VM.Config.Memory VM.Config.Network VM.Config.Options VM.Console VM.PowerMgmt Datastore.AllocateSpace Datastore.Audit Sys.Audit"
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
