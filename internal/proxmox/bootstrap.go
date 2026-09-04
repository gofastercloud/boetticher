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
	"sync"
	"syscall"
	"time"

	"github.com/gofastercloud/boetticher/internal/model"
	networkmodel "github.com/gofastercloud/boetticher/internal/network"
	"github.com/gofastercloud/boetticher/internal/pathguard"
	"github.com/gofastercloud/boetticher/internal/sshconfig"
	"github.com/gofastercloud/boetticher/internal/telemetry"
)

type CommandRunner interface {
	Run(ctx context.Context, address, user, command string) ([]byte, error)
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
		attemptCtx, cancel := context.WithTimeout(ctx, sshAttemptTimeout)
		_, err := runner.Run(attemptCtx, address, user, "true")
		cancel()
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
		attemptCtx, cancel := context.WithTimeout(ctx, sshAttemptTimeout)
		_, err := runner.Run(attemptCtx, address, user, command)
		cancel()
		if err == nil {
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
	Port            int
	KnownHosts      string
	StrictHostKey   string
	IdentityFile    string
	ConfigFile      string
	freshConnection bool
	// HostAlias selects a generated SSH configuration host, including its
	// ProxyJump policy. It does not change the network destination.
	HostAlias string
	// HostKeyAlias supplies OpenSSH's canonical host-key identity while the
	// network target remains the supplied address. It is used for bootstrap
	// connections whose address is not resolvable through HOME DNS.
	HostKeyAlias string
	// identityData is an operation-scoped private key supplied through an
	// inherited file descriptor. It is never written to disk or put in argv.
	identityData []byte
}

// FreshConnection returns a runner that bypasses OpenSSH connection
// multiplexing. It is used for authentication probes where an existing
// control master could outlive a temporary credential and produce a false
// positive.
func (r SSHRunner) FreshConnection() SSHRunner {
	r.freshConnection = true
	return r
}

// WithIdentityData returns a runner that supplies an operation-scoped private
// key from memory. The caller owns the byte slice and must wipe it after the
// bounded operation and its cleanup have completed.
func (r SSHRunner) WithIdentityData(identityData []byte) SSHRunner {
	r.IdentityFile = ""
	r.identityData = identityData
	return r
}

// ClearIdentityData wipes the operation-scoped private key held by the runner.
// Copies of SSHRunner share the same backing slice, so this also clears copies
// retained by short-lived clients or interfaces.
func (r *SSHRunner) ClearIdentityData() {
	if r == nil {
		return
	}
	for index := range r.identityData {
		r.identityData[index] = 0
	}
	r.identityData = nil
}

type SSHPhysicalNetworkDiscovery struct {
	Node      string
	Discovery networkmodel.Discovery
}

const sshAttemptTimeout = 15 * time.Second

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
	if err := enrichNetworkInterfaceHardware(ctx, runner, address, initialUser, interfaces); err != nil {
		return SSHPhysicalNetworkDiscovery{}, fmt.Errorf("HOLD: enrich Proxmox physical network evidence: %w", err)
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
	return r.runArgs(ctx, address, user, quoteRemoteArgs(commandArgs), os.Stdin)
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
	return r.runArgsStream(ctx, address, user, quoteRemoteArgs(commandArgs), os.Stdin, stdout)
}

func quoteRemoteArgs(args []string) []string {
	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = shellQuote(arg)
	}
	return quoted
}

// SSHLocalForward is a bounded, loopback-only SSH port forward used for a
// controller API that is reachable only through the Proxmox management path.
// It is intentionally short-lived and has no public listener.
type SSHLocalForward struct {
	localAddress string
	cancel       context.CancelFunc
	done         chan error
	closeOnce    sync.Once
}

func (f *SSHLocalForward) Address() string {
	if f == nil {
		return ""
	}
	return f.localAddress
}

func (f *SSHLocalForward) Close() error {
	if f == nil {
		return nil
	}
	f.closeOnce.Do(func() {
		f.cancel()
		<-f.done
	})
	return nil
}

// StartLocalForward starts a local loopback forward to targetAddress:targetPort
// through the configured SSH endpoint. The caller must close the returned
// forward when the bounded operation is complete.
func (r SSHRunner) StartLocalForward(ctx context.Context, address, user, targetAddress string, targetPort int) (*SSHLocalForward, error) {
	if ctx == nil {
		return nil, errors.New("SSH local forward context is required")
	}
	if len(r.identityData) > 0 {
		return nil, errors.New("SSH local forward does not support an in-memory operation identity")
	}
	if err := r.validateConfig(); err != nil {
		return nil, err
	}
	localListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("reserve SSH local-forward port: %w", err)
	}
	localPort := localListener.Addr().(*net.TCPAddr).Port
	if err := localListener.Close(); err != nil {
		return nil, fmt.Errorf("release SSH local-forward port: %w", err)
	}
	args, err := r.forwardArgs(address, user, localPort, targetAddress, targetPort)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	status := 1
	defer func() {
		telemetry.Record(ctx, telemetry.Event{
			Category: "ssh", Operation: "local-forward", Target: user + "@" + address,
			Status: status, Duration: time.Since(started), Success: status == 0,
		})
	}()
	forwardContext, cancel := context.WithCancel(ctx)
	command := newSSHProcess(args)
	command.Stdin = nil
	command.Stdout = io.Discard
	stderr := &boundedOutput{limit: 64 << 10}
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start SSH local forward: %w", err)
	}
	done := make(chan error, 1)
	go waitForSSHProcess(forwardContext, command, done)
	forward := &SSHLocalForward{localAddress: fmt.Sprintf("127.0.0.1:%d", localPort), cancel: cancel, done: done}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case err := <-done:
			cancel()
			if err == nil {
				return nil, errors.New("SSH local forward exited before readiness")
			}
			message := strings.TrimSpace(stderr.String())
			if message != "" {
				return nil, fmt.Errorf("SSH local forward exited before readiness: %w: %s", err, message)
			}
			return nil, fmt.Errorf("SSH local forward exited before readiness: %w", err)
		case <-ctx.Done():
			_ = forward.Close()
			return nil, fmt.Errorf("start SSH local forward: %w", ctx.Err())
		case <-ticker.C:
			connection, dialErr := net.DialTimeout("tcp", forward.localAddress, 250*time.Millisecond)
			if dialErr == nil {
				_ = connection.Close()
				status = 0
				return forward, nil
			}
		case <-timeout.C:
			_ = forward.Close()
			message := strings.TrimSpace(stderr.String())
			if message != "" {
				return nil, fmt.Errorf("SSH local forward did not become ready: %s", message)
			}
			return nil, errors.New("SSH local forward did not become ready")
		}
	}
}

const managementInterfaceConfig = `auto vmbr1.99
iface vmbr1.99 inet static
    address 10.10.99.5/24
    vlan-raw-device vmbr1
    up ip route replace 10.10.0.0/16 via 10.10.99.1 dev vmbr1.99
    down ip route del 10.10.0.0/16 via 10.10.99.1 dev vmbr1.99 || true
`

const networkInterfacesSourceDirectory = "source-directory /etc/network/interfaces.d"

func ensureNetworkInterfacesSource(ctx context.Context, runner StdinCommandRunner, address, user string) error {
	content, err := runner.Run(ctx, address, user, privilegedCommand(user, "/bin/cat /etc/network/interfaces"))
	if err != nil {
		return fmt.Errorf("read Proxmox network interfaces configuration: %w", err)
	}
	for _, line := range strings.Split(string(content), "\n") {
		if strings.TrimSpace(line) == networkInterfacesSourceDirectory {
			return nil
		}
	}
	updated := append([]byte(nil), content...)
	if len(updated) > 0 && updated[len(updated)-1] != '\n' {
		updated = append(updated, '\n')
	}
	updated = append(updated, []byte(networkInterfacesSourceDirectory+"\n")...)
	install := privilegedCommand(user, "install -D -m 0644 /dev/stdin /etc/network/interfaces")
	if _, err := runner.RunWithStdin(ctx, address, user, install, bytes.NewReader(updated)); err != nil {
		return fmt.Errorf("enable Proxmox network interfaces directory: %w", err)
	}
	return nil
}

// ConfigureManagementNetwork establishes the fixed virtual-only Proxmox
// management leg. It never changes vmbr0, its member, or the default route.
func ConfigureManagementNetwork(ctx context.Context, runner StdinCommandRunner, address, user string) error {
	if runner == nil {
		return errors.New("management network runner is required")
	}
	if err := ensureNetworkInterfacesSource(ctx, runner, address, user); err != nil {
		return err
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
	if err := r.validateConfig(); err != nil {
		return err
	}
	started := time.Now()
	status := 1
	defer func() {
		telemetry.Record(ctx, telemetry.Event{
			Category: "ssh", Operation: "command", Target: user + "@" + address,
			Status: status, Duration: time.Since(started), Success: status == 0,
		})
	}()
	var isolatedConfigPath string
	if len(r.identityData) > 0 && r.ConfigFile != "" && r.HostAlias != "" {
		configData, configErr := r.isolatedSSHConfig()
		if configErr != nil {
			return configErr
		}
		configFile, createErr := os.CreateTemp("", "boetticher-ssh-config-")
		if createErr != nil {
			return fmt.Errorf("create isolated SSH configuration: %w", createErr)
		}
		isolatedConfigPath = configFile.Name()
		defer os.Remove(isolatedConfigPath)
		if chmodErr := configFile.Chmod(0600); chmodErr != nil {
			_ = configFile.Close()
			return fmt.Errorf("protect isolated SSH configuration: %w", chmodErr)
		}
		if _, writeErr := configFile.Write(configData); writeErr != nil {
			_ = configFile.Close()
			return fmt.Errorf("write isolated SSH configuration: %w", writeErr)
		}
		if closeErr := configFile.Close(); closeErr != nil {
			return fmt.Errorf("close isolated SSH configuration: %w", closeErr)
		}
		r.ConfigFile = isolatedConfigPath
	}
	args, err := r.commandArgs(address, user, commandArgs)
	if err != nil {
		return err
	}
	process := newSSHProcess(args)
	process.Stdin = stdin
	process.Stdout = stdout
	var identityReader, identityWriter *os.File
	if len(r.identityData) > 0 {
		var pipeErr error
		identityReader, identityWriter, pipeErr = os.Pipe()
		if pipeErr != nil {
			return fmt.Errorf("prepare in-memory SSH identity: %w", pipeErr)
		}
		process.ExtraFiles = []*os.File{identityReader}
		defer identityReader.Close()
	}
	stderr := &boundedOutput{limit: 64 << 10}
	process.Stderr = stderr
	if err := process.Start(); err != nil {
		if identityWriter != nil {
			_ = identityWriter.Close()
		}
		return fmt.Errorf("start SSH command: %w", err)
	}
	if identityWriter != nil {
		if _, err := identityWriter.Write(r.identityData); err != nil {
			_ = identityWriter.Close()
			if process.Process != nil {
				_ = syscall.Kill(-process.Process.Pid, syscall.SIGKILL)
			}
			return fmt.Errorf("stream in-memory SSH identity: %w", err)
		}
		if err := identityWriter.Close(); err != nil {
			return fmt.Errorf("close in-memory SSH identity: %w", err)
		}
	}
	done := make(chan error, 1)
	go waitForSSHProcess(ctx, process, done)
	err = <-done
	if err != nil {
		message := strings.TrimSpace(stderr.String())
		if message != "" {
			return fmt.Errorf("SSH bootstrap command failed: %w: %s", err, message)
		}
		return fmt.Errorf("SSH bootstrap command failed: %w", err)
	}
	status = 0
	return nil
}

var sshExecutable = "/usr/bin/ssh"

func newSSHProcess(args []string) *exec.Cmd {
	process := exec.Command(sshExecutable, args...)
	process.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return process
}

func waitForSSHProcess(ctx context.Context, process *exec.Cmd, done chan<- error) {
	wait := make(chan error, 1)
	go func() { wait <- process.Wait() }()
	select {
	case err := <-wait:
		done <- err
	case <-ctx.Done():
		if process.Process != nil {
			_ = syscall.Kill(-process.Process.Pid, syscall.SIGKILL)
		}
		done <- <-wait
	}
}

func (r SSHRunner) validateConfig() error {
	for label, path := range map[string]string{"known-hosts": r.KnownHosts, "identity": r.IdentityFile} {
		if path == "" {
			continue
		}
		if err := pathguard.ValidateNoSymlinkComponents(path); err != nil {
			return fmt.Errorf("validate SSH %s path: %w", label, err)
		}
	}
	if r.ConfigFile == "" {
		return nil
	}
	if err := sshconfig.ValidateExecutionConfig(r.ConfigFile); err != nil {
		return fmt.Errorf("validate SSH execution configuration: %w", err)
	}
	return nil
}

func (r SSHRunner) isolatedSSHConfig() ([]byte, error) {
	if r.ConfigFile == "" || r.HostAlias == "" {
		return nil, errors.New("isolated SSH configuration requires a config file and host alias")
	}
	data, err := os.ReadFile(r.ConfigFile)
	if err != nil {
		return nil, fmt.Errorf("read SSH configuration for temporary identity: %w", err)
	}
	lines := strings.SplitAfter(string(data), "\n")
	inTarget := false
	foundTarget := false
	var filtered strings.Builder
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			filtered.WriteString(line)
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) > 1 && strings.EqualFold(strings.TrimSuffix(fields[0], "="), "host") {
			inTarget = false
			for _, alias := range fields[1:] {
				if alias == r.HostAlias {
					inTarget = true
					foundTarget = true
					break
				}
			}
		}
		if inTarget && len(fields) > 1 && strings.EqualFold(strings.TrimSuffix(fields[0], "="), "identityfile") {
			continue
		}
		filtered.WriteString(line)
	}
	if !foundTarget {
		return nil, fmt.Errorf("isolated SSH configuration has no host alias %q", r.HostAlias)
	}
	return []byte(filtered.String()), nil
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
	if len(commandArgs) == 0 || commandArgs[0] == "" {
		return nil, errors.New("SSH remote command is required")
	}
	args, target, err := r.connectionArgs(address, user, "no")
	if err != nil {
		return nil, err
	}
	args = append(args, target)
	args = append(args, commandArgs...)
	return args, nil
}

func (r SSHRunner) forwardArgs(address, user string, localPort int, targetAddress string, targetPort int) ([]string, error) {
	if localPort < 1 || localPort > 65535 {
		return nil, errors.New("SSH local-forward port is invalid")
	}
	if net.ParseIP(targetAddress) == nil || targetPort < 1 || targetPort > 65535 {
		return nil, errors.New("SSH local-forward target is invalid")
	}
	args, target, err := r.connectionArgs(address, user, "yes")
	if err != nil {
		return nil, err
	}
	forward := fmt.Sprintf("127.0.0.1:%d:%s:%d", localPort, targetAddress, targetPort)
	// Short-lived forwards must create their own forwarding-only connection.
	// Reusing a ControlMaster can make OpenSSH request a shell session as the
	// nologin bastion user, which exits before the forward becomes ready.
	args = append(args, "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ExitOnForwardFailure=yes")
	return append(args, "-N", "-L", forward, target), nil
}

func (r SSHRunner) connectionArgs(address, user, batchMode string) ([]string, string, error) {
	if net.ParseIP(address) == nil {
		return nil, "", fmt.Errorf("Proxmox bootstrap address must be an IP address")
	}
	if user == "" {
		return nil, "", errors.New("bootstrap SSH user is required")
	}
	// Every readiness and cleanup command must have a finite connection
	// boundary. Without this, an unreachable ProxyJump target can leave the
	// deployment waiting indefinitely and can orphan the forwarding process.
	args := []string{"-o", "BatchMode=" + batchMode, "-o", "ConnectTimeout=10", "-o", "ForwardAgent=no", "-o", "ForwardX11=no"}
	strictHostKey := r.StrictHostKey
	if strictHostKey == "" {
		strictHostKey = "ask"
	}
	if strictHostKey == "no" || strictHostKey == "accept-new" {
		return nil, "", errors.New("weak SSH host-key verification mode is not supported")
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
		// The generated deployment path supplies one enrolled operator key. Do
		// not let an unrelated local agent identity consume the server's
		// authentication budget before that key is tried.
		args = append(args, "-o", "IdentitiesOnly=yes", "-i", r.IdentityFile)
	} else if len(r.identityData) > 0 {
		// runArgsStream supplies an isolated config when a generated host alias
		// is used. Its target block has no durable operator identity; the
		// bastion block retains that identity so ProxyJump can still authenticate.
		args = append(args, "-o", "IdentitiesOnly=yes", "-i", "/dev/fd/3")
	}
	if r.HostKeyAlias != "" {
		if !safeNodeID(r.HostKeyAlias) {
			return nil, "", errors.New("SSH host-key alias is not a safe identifier")
		}
		args = append(args, "-o", "HostKeyAlias="+r.HostKeyAlias)
	}
	if r.freshConnection {
		args = append(args, "-o", "ControlMaster=no", "-o", "ControlPath=none")
	}
	target := address
	if r.HostAlias != "" {
		if !safeID(r.HostAlias) {
			return nil, "", errors.New("SSH host alias is not a safe identifier")
		}
		target = r.HostAlias
	}
	return args, user + "@" + target, nil
}

// InstallTemporaryRootAccess installs one exact operation-scoped root key on
// the host. The caller must authenticate this one mutation with independent
// operator recovery authority, only after the immutable Apply plan is
// accepted. Cleanup removes this exact public-key line and does not alter any
// other root key, password, or SSH policy.
func InstallTemporaryRootAccess(ctx context.Context, runner CommandRunner, address, user, publicKey string) error {
	if runner == nil {
		return errors.New("temporary root acquisition runner is required")
	}
	if user != "root" {
		return errors.New("temporary root acquisition requires the root recovery transport")
	}
	if err := validatePublicKey(publicKey); err != nil {
		return fmt.Errorf("temporary root acquisition key: %w", err)
	}
	command := "set -eu; umask 077; install -d -m 700 -o root -g root /root/.ssh; touch /root/.ssh/authorized_keys; chown root:root /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys; grep -qxF -- " + shellQuote(publicKey) + " /root/.ssh/authorized_keys || printf '%s\\n' " + shellQuote(publicKey) + " >> /root/.ssh/authorized_keys"
	if _, err := runner.Run(ctx, address, user, command); err != nil {
		return fmt.Errorf("install temporary root access: %w", err)
	}
	return nil
}

func ConfigureIdentities(ctx context.Context, runner CommandRunner, address, initialUser, adminPublicKey string, allowedDestinations []string) error {
	if err := validatePublicKey(adminPublicKey); err != nil {
		return err
	}
	if len(allowedDestinations) == 0 {
		return errors.New("at least one bastion destination is required")
	}
	for _, destination := range allowedDestinations {
		host, port, splitErr := net.SplitHostPort(destination)
		if splitErr != nil || net.ParseIP(host) == nil || (port != "22" && port != "443") || strings.ContainsAny(destination, "'\n\r") {
			return fmt.Errorf("invalid bastion destination %q", destination)
		}
	}
	// Public keys and destination addresses are the only values interpolated;
	// credentials are never placed in this command.
	jumpKey := "restrict,port-forwarding,permitopen=\"" + strings.Join(allowedDestinations, "\",permitopen=\"") + "\" " + publicKeyLine(adminPublicKey)
	command := "set -eu; if ! command -v visudo >/dev/null 2>&1; then apt_sources=\"$(mktemp /run/boetticher-apt-sources.XXXXXX)\"; trap 'rm -f \"$apt_sources\"' EXIT; printf '%s\\n' 'deb http://deb.debian.org/debian trixie main' 'deb http://deb.debian.org/debian trixie-updates main' 'deb http://security.debian.org/debian-security trixie-security main' > \"$apt_sources\"; apt-get -o Dir::Etc::sourcelist=\"$apt_sources\" -o Dir::Etc::sourceparts=- -o Acquire::Retries=3 update; apt-get -o Dir::Etc::sourcelist=\"$apt_sources\" -o Dir::Etc::sourceparts=- -o Acquire::Retries=3 install --yes --no-install-recommends sudo; fi; id -u labadmin >/dev/null 2>&1 || useradd --create-home --shell /bin/bash labadmin; passwd --lock labadmin; gpasswd --delete labadmin sudo >/dev/null 2>&1 || true; id -u lab-jump >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin lab-jump; install -d -m 700 -o lab-jump -g lab-jump /home/lab-jump; install -d -m 700 /home/labadmin/.ssh /etc/ssh/sshd_config.d; install -m 600 /dev/null /home/labadmin/.ssh/authorized_keys; grep -qxF " + shellQuote(adminPublicKey) + " /home/labadmin/.ssh/authorized_keys || printf '%s\\n' " + shellQuote(adminPublicKey) + " >> /home/labadmin/.ssh/authorized_keys; install -m 600 /dev/null /home/lab-jump.authorized_keys; printf '%s\\n' " + shellQuote(jumpKey) + " > /home/lab-jump.authorized_keys; chown lab-jump:lab-jump /home/lab-jump.authorized_keys; chown -R labadmin:labadmin /home/labadmin/.ssh; rm -f /etc/sudoers.d/boetticher-labadmin; cat > /etc/ssh/sshd_config.d/90-boetticher-jump.conf <<'EOF'\nAllowUsers root labadmin lab-jump lab-netprobe\nMatch User lab-jump\n    AuthorizedKeysFile /home/lab-jump.authorized_keys\n    PermitTTY no\n    X11Forwarding no\n    AllowAgentForwarding no\n    AllowTcpForwarding local\n    PermitOpen " + strings.Join(allowedDestinations, " ") + "\nEOF\nvisudo -cf /etc/sudoers\nsshd -t\nsystemctl reload ssh || systemctl reload sshd"
	_, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, command))
	return err
}

// ConfigureBastionPolicy reconciles only the host-side restricted jump policy.
// It deliberately does not install or modify any user key, so Apply can
// refresh the policy while its temporary root key remains the only
// deployment-owned root identity.
func ConfigureBastionPolicy(ctx context.Context, runner CommandRunner, address, user string, allowedDestinations []string) error {
	if runner == nil {
		return errors.New("bastion policy runner is required")
	}
	if len(allowedDestinations) == 0 {
		return errors.New("at least one bastion destination is required")
	}
	for _, destination := range allowedDestinations {
		host, port, splitErr := net.SplitHostPort(destination)
		if splitErr != nil || net.ParseIP(host) == nil || (port != "22" && port != "443") || strings.ContainsAny(destination, "'\n\r") {
			return fmt.Errorf("invalid bastion destination %q", destination)
		}
	}
	command := "set -eu; install -d -m 700 /etc/ssh/sshd_config.d; cat > /etc/ssh/sshd_config.d/90-boetticher-jump.conf <<'EOF'\nAllowUsers root labadmin lab-jump lab-netprobe\nMatch User lab-jump\n    AuthorizedKeysFile /home/lab-jump.authorized_keys\n    PermitTTY no\n    X11Forwarding no\n    AllowAgentForwarding no\n    AllowTcpForwarding local\n    PermitOpen " + strings.Join(allowedDestinations, " ") + "\nEOF\nsshd -t\nsystemctl reload ssh || systemctl reload sshd"
	if _, err := runner.Run(ctx, address, user, privilegedCommand(user, command)); err != nil {
		return fmt.Errorf("configure host bastion policy: %w", err)
	}
	return nil
}

// ConfigureHeadlessPowerPolicy makes a Proxmox host safe to operate as an
// unattended appliance on laptop-class hardware. The policy is explicit so a
// distribution default or a vendor-specific laptop setting cannot suspend the
// host when its lid closes or when no interactive session is present.
func ConfigureHeadlessPowerPolicy(ctx context.Context, runner CommandRunner, address, user string) error {
	if runner == nil {
		return errors.New("headless power policy runner is required")
	}
	command := "set -eu; dir=/etc/systemd/logind.conf.d; file=$dir/90-boetticher-headless.conf; install -d -m 755 \"$dir\"; tmp=$(mktemp \"$file.XXXXXX\"); trap 'rm -f \"$tmp\"' EXIT; printf '%s\\n' '[Login]' 'HandleLidSwitch=ignore' 'HandleLidSwitchExternalPower=ignore' 'HandleLidSwitchDocked=ignore' 'HandleSuspendKey=ignore' 'HandleHibernateKey=ignore' 'IdleAction=ignore' >\"$tmp\"; install -m 644 \"$tmp\" \"$file\"; systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target; systemctl restart systemd-logind"
	if _, err := runner.Run(ctx, address, user, privilegedCommand(user, command)); err != nil {
		return fmt.Errorf("configure headless power policy: %w", err)
	}
	return nil
}

// CheckHeadlessPowerPolicy verifies the host policy without changing it.
func CheckHeadlessPowerPolicy(ctx context.Context, runner CommandRunner, address, user string) error {
	if runner == nil {
		return errors.New("headless power policy check runner is required")
	}
	command := "set -eu; file=/etc/systemd/logind.conf.d/90-boetticher-headless.conf; for setting in 'HandleLidSwitch=ignore' 'HandleLidSwitchExternalPower=ignore' 'HandleLidSwitchDocked=ignore' 'HandleSuspendKey=ignore' 'HandleHibernateKey=ignore' 'IdleAction=ignore'; do grep -qxF \"$setting\" \"$file\"; done; for unit in sleep.target suspend.target hibernate.target hybrid-sleep.target; do systemctl is-enabled \"$unit\" 2>&1 | grep -qxF masked; done"
	if _, err := runner.Run(ctx, address, user, privilegedCommand(user, command)); err != nil {
		return fmt.Errorf("headless power policy is not active: %w", err)
	}
	return nil
}

// RestoreTemporaryRootAccess re-arms the deployment-only root key inside one
// already-owned guest after a prior successful deployment cleaned it up. The
// authenticated Proxmox root transport is the only authority used to cross
// the guest boundary; the key remains temporary and is removed by
// RevokeTemporaryRootAccess after convergence.
func RestoreTemporaryRootAccess(ctx context.Context, runner CommandRunner, address, user string, kind GuestKind, vmid int, publicKey string) error {
	if runner == nil {
		return errors.New("temporary root restore runner is required")
	}
	if user != "root" {
		return errors.New("temporary root restore requires the root transport")
	}
	if vmid <= 0 {
		return errors.New("temporary root restore requires a positive guest VMID")
	}
	if kind != KindQEMU && kind != KindLXC {
		return fmt.Errorf("temporary root restore does not support guest kind %q", kind)
	}
	if err := validatePublicKey(publicKey); err != nil {
		return fmt.Errorf("temporary root restore key: %w", err)
	}
	guestCommand := "set -eu; install -d -m 700 -o root -g root /root/.ssh; touch /root/.ssh/authorized_keys; chown root:root /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys; grep -qxF -- " + shellQuote(publicKey) + " /root/.ssh/authorized_keys || printf '%s\\n' " + shellQuote(publicKey) + " >> /root/.ssh/authorized_keys"
	var command string
	switch kind {
	case KindQEMU:
		command = fmt.Sprintf("/usr/sbin/qm guest exec %d -- /bin/sh -c %s", vmid, shellQuote(guestCommand))
	case KindLXC:
		command = fmt.Sprintf("/usr/sbin/pct exec %d -- /bin/sh -c %s", vmid, shellQuote(guestCommand))
	}
	output, err := runner.Run(ctx, address, user, command)
	if err != nil {
		return fmt.Errorf("restore temporary root access in guest %d: %w", vmid, err)
	}
	if kind == KindQEMU {
		var result map[string]json.RawMessage
		if err := json.Unmarshal(bytes.TrimSpace(output), &result); err != nil {
			return fmt.Errorf("decode guest-agent restore result for guest %d: %w", vmid, err)
		}
		var exited int
		var exitCode int
		if err := json.Unmarshal(result["exited"], &exited); err != nil {
			return fmt.Errorf("decode guest-agent completion for guest %d: %w", vmid, err)
		}
		if err := json.Unmarshal(result["exitcode"], &exitCode); err != nil {
			return fmt.Errorf("decode guest-agent exit code for guest %d: %w", vmid, err)
		}
		if exited != 1 {
			return fmt.Errorf("guest-agent restore for guest %d did not finish", vmid)
		}
		if exitCode != 0 {
			var errData string
			_ = json.Unmarshal(result["err-data"], &errData)
			if errData != "" {
				return fmt.Errorf("guest-agent restore for guest %d exited %d: %s", vmid, exitCode, strings.TrimSpace(errData))
			}
			return fmt.Errorf("guest-agent restore for guest %d exited %d", vmid, exitCode)
		}
	}
	return nil
}

var retainedModuleServices = map[string][]string{
	"tailnet-router": {"tailscaled"},
	"airvpn":         {"boetticher-airvpn.service"},
	"bifrost":        {"bifrost", "nginx"},
	"printer":        {"octoprint", "nginx"},
	"arr":            {"sonarr", "radarr", "nginx"},
	"aiops":          {"boetticher-aiops", "boetticher-aiops.socket", "holmes"},
	"gatus":          {"gatus", "nginx"},
}

// InactivateRetainedModule stops and disables only the declared service set
// for one product-owned retained guest. It deliberately crosses the guest
// boundary through authenticated Proxmox guest execution rather than relying
// on the guest network, which may correctly be blocked by the modeled
// firewall. The fixed service map prevents a retained declaration from
// turning this operation into arbitrary guest command execution.
func InactivateRetainedModule(ctx context.Context, runner CommandRunner, address, user string, kind GuestKind, vmid int, module string) error {
	if runner == nil {
		return errors.New("retained module inactivation runner is required")
	}
	if user != "root" {
		return errors.New("retained module inactivation requires the root transport")
	}
	if vmid <= 0 {
		return errors.New("retained module inactivation requires a positive guest VMID")
	}
	if kind != KindQEMU && kind != KindLXC {
		return fmt.Errorf("retained module inactivation does not support guest kind %q", kind)
	}
	services, ok := retainedModuleServices[module]
	if !ok {
		return fmt.Errorf("retained module %q has no bounded service contract", module)
	}
	serviceCommands := make([]string, 0, len(services))
	for _, service := range services {
		serviceCommands = append(serviceCommands, "systemctl disable --now "+shellQuote(service)+"; if systemctl is-active --quiet "+shellQuote(service)+"; then echo retained service remains active: "+shellQuote(service)+" >&2; exit 1; fi; if systemctl is-enabled --quiet "+shellQuote(service)+"; then echo retained service remains enabled: "+shellQuote(service)+" >&2; exit 1; fi")
	}
	guestCommand := "set -eu; systemctl daemon-reload; " + strings.Join(serviceCommands, "; ")
	var command string
	switch kind {
	case KindQEMU:
		command = fmt.Sprintf("/usr/sbin/qm guest exec %d -- /bin/sh -c %s", vmid, shellQuote(guestCommand))
	case KindLXC:
		command = fmt.Sprintf("/usr/sbin/pct exec %d -- /bin/sh -c %s", vmid, shellQuote(guestCommand))
	}
	output, err := runner.Run(ctx, address, user, privilegedCommand(user, command))
	if err != nil {
		return fmt.Errorf("inactivate retained %s guest %d: %w", module, vmid, err)
	}
	if kind == KindQEMU {
		var result map[string]json.RawMessage
		if err := json.Unmarshal(bytes.TrimSpace(output), &result); err != nil {
			return fmt.Errorf("decode guest-agent inactivation result for guest %d: %w", vmid, err)
		}
		var exited int
		var exitCode int
		if err := json.Unmarshal(result["exited"], &exited); err != nil {
			return fmt.Errorf("decode guest-agent completion for guest %d: %w", vmid, err)
		}
		if err := json.Unmarshal(result["exitcode"], &exitCode); err != nil {
			return fmt.Errorf("decode guest-agent exit code for guest %d: %w", vmid, err)
		}
		if exited != 1 {
			return fmt.Errorf("guest-agent inactivation for guest %d did not finish", vmid)
		}
		if exitCode != 0 {
			var errData string
			_ = json.Unmarshal(result["err-data"], &errData)
			if errData != "" {
				return fmt.Errorf("guest-agent inactivation for guest %d exited %d: %s", vmid, exitCode, strings.TrimSpace(errData))
			}
			return fmt.Errorf("guest-agent inactivation for guest %d exited %d", vmid, exitCode)
		}
	}
	return nil
}

const guestHostPublicKeyPath = "/var/lib/boetticher/identity/ssh/ssh_host_ed25519_key.pub"

// ReadGuestHostKey obtains the appliance's generated host key through the
// already-authenticated Proxmox host boundary. It is intentionally separate
// from ssh-keyscan: network observations cannot establish the identity used
// for the subsequent root or credential-bearing connection.
func ReadGuestHostKey(ctx context.Context, runner CommandRunner, address, user string, kind GuestKind, vmid int) (string, error) {
	return readGuestHostKey(ctx, runner, address, user, kind, vmid, guestHostPublicKeyPath, true)
}

func readGuestHostKey(ctx context.Context, runner CommandRunner, address, user string, kind GuestKind, vmid int, publicKeyPath string, rootOnly bool) (string, error) {
	if runner == nil {
		return "", errors.New("guest host-key reader is required")
	}
	if rootOnly && user != "root" {
		return "", errors.New("guest host-key read requires the root transport")
	}
	if vmid <= 0 {
		return "", errors.New("guest host-key read requires a positive guest VMID")
	}
	var command string
	switch kind {
	case KindQEMU:
		command = fmt.Sprintf("/usr/sbin/qm guest exec %d -- /bin/cat %s", vmid, publicKeyPath)
	case KindLXC:
		command = fmt.Sprintf("/usr/sbin/pct exec %d -- /bin/cat %s", vmid, publicKeyPath)
	default:
		return "", fmt.Errorf("guest host-key read does not support guest kind %q", kind)
	}
	command = privilegedCommand(user, command)
	output, err := runner.Run(ctx, address, user, command)
	if err != nil {
		return "", fmt.Errorf("read guest host key through Proxmox: %w", err)
	}
	if kind == KindQEMU {
		var result map[string]json.RawMessage
		if err := json.Unmarshal(bytes.TrimSpace(output), &result); err != nil {
			return "", fmt.Errorf("decode guest-agent host-key result: %w", err)
		}
		var exited, exitCode int
		if err := json.Unmarshal(result["exited"], &exited); err != nil || exited != 1 {
			return "", errors.New("guest-agent host-key read did not finish")
		}
		if err := json.Unmarshal(result["exitcode"], &exitCode); err != nil {
			return "", fmt.Errorf("decode guest-agent host-key exit code: %w", err)
		}
		if exitCode != 0 {
			return "", fmt.Errorf("guest-agent host-key read exited %d", exitCode)
		}
		var outData string
		if err := json.Unmarshal(result["out-data"], &outData); err != nil {
			return "", fmt.Errorf("decode guest-agent host-key output: %w", err)
		}
		output = []byte(outData)
	}
	return normalizeGuestHostKey(string(output))
}

func normalizeGuestHostKey(value string) (string, error) {
	fields := strings.Fields(strings.TrimSpace(value))
	if len(fields) < 2 || len(fields) > 3 || fields[0] != "ssh-ed25519" {
		return "", errors.New("guest host key is not one ssh-ed25519 public-key line")
	}
	if err := ValidatePublicKey(strings.Join(fields[:2], " ")); err != nil {
		return "", fmt.Errorf("guest host key is malformed: %w", err)
	}
	return strings.Join(fields[:2], " "), nil
}

func removeTemporaryAuthorizedKeyCommand(publicKey string) string {
	return "root_file=/root/.ssh/authorized_keys; root_tmp=/root/.ssh/authorized_keys.boetticher-cleanup; admin_file=/home/labadmin/.ssh/authorized_keys; admin_tmp=/home/labadmin/.ssh/authorized_keys.boetticher-cleanup; trap 'rm -f \"$root_tmp\" \"$admin_tmp\"' EXIT; remove_key() { file=\"$1\"; tmp=\"$2\"; owner=\"$3\"; group=\"$4\"; if [ -f \"$file\" ]; then if grep -Fvx -- " + shellQuote(publicKey) + " \"$file\" >\"$tmp\"; then install -m 600 -o \"$owner\" -g \"$group\" \"$tmp\" \"$file\"; else status=$?; [ \"$status\" -eq 1 ] || exit \"$status\"; rm -f \"$file\"; fi; fi; }; remove_key \"$root_file\" \"$root_tmp\" root root; remove_key \"$admin_file\" \"$admin_tmp\" labadmin labadmin"
}

// RevokeTemporaryRootAccess removes one exact deployment-only root SSH
// identity from an owned host or guest. It never changes independent operator
// recovery keys, root password state, or the host's root AllowUsers contract.
// The operation is idempotent for retry-safe cleanup.
func RevokeTemporaryRootAccess(ctx context.Context, runner CommandRunner, address, user, publicKey string, host bool) error {
	if runner == nil {
		return errors.New("temporary root cleanup runner is required")
	}
	if user != "root" {
		return errors.New("temporary root cleanup requires the root transport")
	}
	if err := validatePublicKey(publicKey); err != nil {
		return fmt.Errorf("temporary root cleanup key: %w", err)
	}
	removeKey := removeTemporaryAuthorizedKeyCommand(publicKey)
	command := "set -eu; " + removeKey
	if host {
		command += "; file=/etc/ssh/sshd_config.d/90-boetticher-jump.conf; grep -qxF 'AllowUsers root labadmin lab-jump lab-netprobe' \"$file\"; sshd -t"
	}
	if _, err := runner.Run(ctx, address, user, command); err != nil {
		return fmt.Errorf("revoke temporary root access: %w", err)
	}
	return nil
}

// RevokeTemporaryRootAccessThroughHost removes the exact deployment-only key
// from one guest through the independent Proxmox root recovery transport. It
// is the cleanup fallback when the guest network or guest SSH service is no
// longer available after an interrupted Apply.
func RevokeTemporaryRootAccessThroughHost(ctx context.Context, runner CommandRunner, address, user string, kind GuestKind, vmid int, publicKey string) error {
	if runner == nil {
		return errors.New("temporary guest cleanup runner is required")
	}
	if user != "root" {
		return errors.New("temporary guest cleanup requires the root transport")
	}
	if vmid <= 0 {
		return errors.New("temporary guest cleanup requires a positive guest VMID")
	}
	if kind != KindQEMU && kind != KindLXC {
		return fmt.Errorf("temporary guest cleanup does not support guest kind %q", kind)
	}
	if err := validatePublicKey(publicKey); err != nil {
		return fmt.Errorf("temporary guest cleanup key: %w", err)
	}
	guestCommand := "set -eu; " + removeTemporaryAuthorizedKeyCommand(publicKey)
	var command string
	switch kind {
	case KindQEMU:
		command = fmt.Sprintf("/usr/sbin/qm guest exec %d -- /bin/sh -c %s", vmid, shellQuote(guestCommand))
	case KindLXC:
		command = fmt.Sprintf("/usr/sbin/pct exec %d -- /bin/sh -c %s", vmid, shellQuote(guestCommand))
	}
	output, err := runner.Run(ctx, address, user, command)
	if err != nil {
		return fmt.Errorf("revoke temporary root access in guest %d through Proxmox: %w", vmid, err)
	}
	if kind == KindQEMU {
		var result map[string]json.RawMessage
		if err := json.Unmarshal(bytes.TrimSpace(output), &result); err != nil {
			return fmt.Errorf("decode guest-agent cleanup result for guest %d: %w", vmid, err)
		}
		var exited, exitCode int
		if err := json.Unmarshal(result["exited"], &exited); err != nil || exited != 1 {
			return fmt.Errorf("guest-agent cleanup for guest %d did not finish", vmid)
		}
		if err := json.Unmarshal(result["exitcode"], &exitCode); err != nil {
			return fmt.Errorf("decode guest-agent cleanup exit code for guest %d: %w", vmid, err)
		}
		if exitCode != 0 {
			var errData string
			_ = json.Unmarshal(result["err-data"], &errData)
			if errData != "" {
				return fmt.Errorf("guest-agent cleanup for guest %d exited %d: %s", vmid, exitCode, strings.TrimSpace(errData))
			}
			return fmt.Errorf("guest-agent cleanup for guest %d exited %d", vmid, exitCode)
		}
	}
	return nil
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

func CreateScopedCredentials(ctx context.Context, runner CommandRunner, address, initialUser, userID, tokenID, node string) (string, error) {
	return CreateScopedCredentialsWithRole(ctx, runner, address, initialUser, userID, tokenID, "BoetticherProvisioner", node)
}

// CheckScopedCredentialAvailability verifies the reserved provisioning
// identity before bootstrap performs any host mutation. An existing token is
// not adoptable because Proxmox does not reveal its secret again.
func CheckScopedCredentialAvailability(ctx context.Context, runner CommandRunner, address, initialUser, userID, tokenID, role string) error {
	if !safeID(userID) || !safeID(tokenID) || !safeID(role) {
		return errors.New("Proxmox identity and token IDs must be simple identifiers")
	}
	roleOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, "pvesh get /access/roles --output-format json"))
	if err != nil {
		return fmt.Errorf("HOLD: inspect Proxmox role %q: %w", role, err)
	}
	if _, err := validateScopedRoleJSON(roleOutput, role, ScopedProvisionerPrivileges()); err != nil {
		return fmt.Errorf("HOLD: Proxmox role %q is not the expected bounded role: %w", role, err)
	}
	usersOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, "pvesh get /access/users --output-format json"))
	if err != nil {
		return fmt.Errorf("HOLD: inspect Proxmox users: %w", err)
	}
	users, err := accessIDs(usersOutput, "userid", "id")
	if err != nil {
		return fmt.Errorf("HOLD: decode Proxmox users: %w", err)
	}
	if !users[userID] {
		return nil
	}
	tokensOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, "pvesh get /access/users/"+shellQuote(userID)+"/token --output-format json"))
	if err != nil {
		return fmt.Errorf("HOLD: inspect Proxmox tokens for %s: %w", userID, err)
	}
	tokens, err := accessIDs(tokensOutput, "tokenid", "id")
	if err != nil {
		return fmt.Errorf("HOLD: decode Proxmox tokens: %w", err)
	}
	if tokens[tokenID] {
		return errors.New("HOLD: the requested Proxmox token already exists; remove the exact owned identity or provide its encrypted credentials")
	}
	return nil
}

const scopedCredentialComment = "boetticher automation identity"

// RemoveExactScopedCredentialToken removes only the reserved, stale
// provisioning token when the caller has deliberately started a new site and
// cannot recover Proxmox's one-time token value. The surrounding role must
// still be the exact bounded Boetticher role; it never removes the user,
// role, root access, or any other token.
func RemoveExactScopedCredentialToken(ctx context.Context, runner CommandRunner, address, initialUser, userID, tokenID, role, node string) (bool, error) {
	if !safeID(userID) || !safeID(tokenID) || !safeID(role) {
		return false, errors.New("Proxmox identity and token IDs must be simple identifiers")
	}
	roleOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, "pvesh get /access/roles --output-format json"))
	if err != nil {
		return false, fmt.Errorf("HOLD: inspect Proxmox role %q before token replacement: %w", role, err)
	}
	roleExists, err := validateScopedRoleJSON(roleOutput, role, ScopedProvisionerPrivileges())
	if err != nil {
		return false, fmt.Errorf("HOLD: Proxmox role %q is not the expected bounded role: %w", role, err)
	}
	if !roleExists {
		return false, fmt.Errorf("HOLD: Proxmox role %q is not present for exact token replacement", role)
	}
	usersOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, "pvesh get /access/users --output-format json"))
	if err != nil {
		return false, fmt.Errorf("HOLD: inspect Proxmox users before token replacement: %w", err)
	}
	users, err := accessIDs(usersOutput, "userid", "id")
	if err != nil {
		return false, fmt.Errorf("HOLD: decode Proxmox users before token replacement: %w", err)
	}
	if !users[userID] {
		return false, nil
	}
	tokensCommand := "pvesh get /access/users/" + shellQuote(userID) + "/token --output-format json"
	tokensOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, tokensCommand))
	if err != nil {
		return false, fmt.Errorf("HOLD: inspect Proxmox tokens for %s before replacement: %w", userID, err)
	}
	tokens, err := accessIDs(tokensOutput, "tokenid", "id")
	if err != nil {
		return false, fmt.Errorf("HOLD: decode Proxmox tokens before replacement: %w", err)
	}
	if !tokens[tokenID] {
		return false, nil
	}
	aclOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, "pvesh get /access/acl --output-format json"))
	if err != nil {
		return false, fmt.Errorf("HOLD: inspect Proxmox ACLs before token replacement: %w", err)
	}
	if err := validateScopedCredentialTokenOwnership(usersOutput, tokensOutput, aclOutput, userID, tokenID, role, node); err != nil {
		return false, fmt.Errorf("HOLD: scoped Proxmox token ownership is not the expected Boetticher identity: %w", err)
	}
	if err := removeLegacyScopedCredentialACLs(ctx, runner, address, initialUser, aclOutput, userID, tokenID, role); err != nil {
		return false, fmt.Errorf("HOLD: remove legacy root ACLs for scoped Proxmox token: %w", err)
	}
	removeToken := "pvesh delete /access/users/" + shellQuote(userID) + "/token/" + shellQuote(tokenID)
	if _, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, removeToken)); err != nil {
		return false, fmt.Errorf("remove exact stale Proxmox token %s!%s: %w", userID, tokenID, err)
	}
	remainingOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, tokensCommand))
	if err != nil {
		return false, fmt.Errorf("verify Proxmox token removal for %s: %w", userID, err)
	}
	remaining, err := accessIDs(remainingOutput, "tokenid", "id")
	if err != nil {
		return false, fmt.Errorf("HOLD: decode Proxmox tokens after replacement: %w", err)
	}
	if remaining[tokenID] {
		return false, fmt.Errorf("HOLD: exact stale Proxmox token %s!%s remains after deletion", userID, tokenID)
	}
	return true, nil
}

// CheckScopedCredentialReuse verifies that an encrypted, previously-created
// provisioning identity still exists with the expected bounded role. It is
// read-only and permits safe retry/bootstrap qualification without treating
// the exact owned token as an unrelated collision.
func CheckScopedCredentialReuse(ctx context.Context, runner CommandRunner, address, initialUser, userID, tokenID, role string) error {
	if !safeID(userID) || !safeID(tokenID) || !safeID(role) {
		return errors.New("Proxmox identity and token IDs must be simple identifiers")
	}
	roleOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, "pvesh get /access/roles --output-format json"))
	if err != nil {
		return fmt.Errorf("HOLD: inspect Proxmox role %q: %w", role, err)
	}
	if _, err := validateScopedRoleJSON(roleOutput, role, ScopedProvisionerPrivileges()); err != nil {
		return fmt.Errorf("HOLD: Proxmox role %q is not the expected bounded role: %w", role, err)
	}
	usersOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, "pvesh get /access/users --output-format json"))
	if err != nil {
		return fmt.Errorf("HOLD: inspect Proxmox users: %w", err)
	}
	users, err := accessIDs(usersOutput, "userid", "id")
	if err != nil {
		return fmt.Errorf("HOLD: decode Proxmox users: %w", err)
	}
	if !users[userID] {
		return fmt.Errorf("HOLD: encrypted Proxmox credentials reference missing user %s", userID)
	}
	if err := validateScopedCredentialUserOwnership(usersOutput, userID); err != nil {
		return fmt.Errorf("HOLD: encrypted Proxmox credentials reference an unexpected user %s: %w", userID, err)
	}
	tokensOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, "pvesh get /access/users/"+shellQuote(userID)+"/token --output-format json"))
	if err != nil {
		return fmt.Errorf("HOLD: inspect Proxmox tokens for %s: %w", userID, err)
	}
	tokens, err := accessIDs(tokensOutput, "tokenid", "id")
	if err != nil {
		return fmt.Errorf("HOLD: decode Proxmox tokens: %w", err)
	}
	if !tokens[tokenID] {
		return fmt.Errorf("HOLD: encrypted Proxmox credentials reference missing token %s!%s", userID, tokenID)
	}
	if err := validateScopedCredentialTokenMetadata(tokensOutput, tokenID); err != nil {
		return fmt.Errorf("HOLD: encrypted Proxmox credentials reference an unexpected token %s!%s: %w", userID, tokenID, err)
	}
	return nil
}

const (
	PulseMonitoringUser  = "pulse-monitor@pve"
	PulseMonitoringToken = "boetticher-monitoring"
	PulseMonitoringRole  = "PVEAuditor"
	// Proxmox marks built-in roles as special; the exact read-only set remains
	// the safety boundary for the Pulse identity.
	pulseMonitoringPrivileges = "Datastore.Audit Mapping.Audit Pool.Audit SDN.Audit Sys.Audit VM.Audit VM.GuestAgent.Audit"
)

// CreatePulseMonitoringCredentials creates the API-only identity used by the
// Pulse server. The built-in PVEAuditor role is assigned at the root path to
// both the service user and its privilege-separated token; no VM mutation,
// guest agent, SSH, datastore-admin, or root monitoring privilege is granted.
func CreatePulseMonitoringCredentials(ctx context.Context, runner CommandRunner, address, initialUser string) (string, error) {
	if runner == nil || address == "" || initialUser == "" {
		return "", errors.New("Pulse monitoring credential bootstrap inputs are invalid")
	}
	rolesOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, "pvesh get /access/roles --output-format json"))
	if err != nil {
		return "", fmt.Errorf("HOLD: inspect Proxmox monitoring roles: %w", err)
	}
	if err := requireBuiltInRole(rolesOutput, PulseMonitoringRole, pulseMonitoringPrivileges); err != nil {
		return "", fmt.Errorf("HOLD: Proxmox monitoring role %q is unavailable: %w", PulseMonitoringRole, err)
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
	} else if err := validatePulseMonitoringUserOwnership(usersOutput); err != nil {
		return "", fmt.Errorf("HOLD: Pulse monitoring user ownership is not the expected Boetticher identity: %w", err)
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

// ReplacePulseMonitoringCredentials rotates the one-time Pulse monitoring
// token when the encrypted token value was deliberately removed with a prior
// site reset. It proves the exact user, privilege-separated token, and both
// read-only ACLs before deleting only that token, then delegates creation to
// the ordinary bounded credential path. It never removes the service user,
// built-in role, or any unrelated token.
func ReplacePulseMonitoringCredentials(ctx context.Context, runner CommandRunner, address, initialUser string) (string, error) {
	if runner == nil || address == "" || initialUser == "" {
		return "", errors.New("Pulse monitoring credential replacement inputs are invalid")
	}
	rolesOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, "pvesh get /access/roles --output-format json"))
	if err != nil {
		return "", fmt.Errorf("HOLD: inspect Proxmox monitoring roles before token replacement: %w", err)
	}
	if err := requireBuiltInRole(rolesOutput, PulseMonitoringRole, pulseMonitoringPrivileges); err != nil {
		return "", fmt.Errorf("HOLD: Proxmox monitoring role %q is unavailable before token replacement: %w", PulseMonitoringRole, err)
	}
	usersOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, "pvesh get /access/users --output-format json"))
	if err != nil {
		return "", fmt.Errorf("HOLD: inspect Pulse monitoring users before token replacement: %w", err)
	}
	users, err := accessIDs(usersOutput, "userid", "id")
	if err != nil {
		return "", fmt.Errorf("HOLD: decode Pulse monitoring users before token replacement: %w", err)
	}
	if !users[PulseMonitoringUser] {
		return CreatePulseMonitoringCredentials(ctx, runner, address, initialUser)
	}
	tokensCommand := "pvesh get /access/users/" + shellQuote(PulseMonitoringUser) + "/token --output-format json"
	tokensOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, tokensCommand))
	if err != nil {
		return "", fmt.Errorf("HOLD: inspect Pulse monitoring tokens before token replacement: %w", err)
	}
	tokens, err := accessIDs(tokensOutput, "tokenid", "id")
	if err != nil {
		return "", fmt.Errorf("HOLD: decode Pulse monitoring tokens before token replacement: %w", err)
	}
	if !tokens[PulseMonitoringToken] {
		return CreatePulseMonitoringCredentials(ctx, runner, address, initialUser)
	}
	aclOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, "pvesh get /access/acl --output-format json"))
	if err != nil {
		return "", fmt.Errorf("HOLD: inspect Pulse monitoring ACLs before token replacement: %w", err)
	}
	if err := validatePulseMonitoringTokenOwnership(usersOutput, tokensOutput, aclOutput); err != nil {
		return "", fmt.Errorf("HOLD: Pulse monitoring token ownership is not the expected Boetticher identity: %w", err)
	}
	removeToken := "pvesh delete /access/users/" + shellQuote(PulseMonitoringUser) + "/token/" + shellQuote(PulseMonitoringToken)
	if _, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, removeToken)); err != nil {
		return "", fmt.Errorf("remove exact stale Pulse monitoring token: %w", err)
	}
	remainingOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, tokensCommand))
	if err != nil {
		return "", fmt.Errorf("verify Pulse monitoring token removal: %w", err)
	}
	remaining, err := accessIDs(remainingOutput, "tokenid", "id")
	if err != nil {
		return "", fmt.Errorf("HOLD: decode Pulse monitoring tokens after replacement: %w", err)
	}
	if remaining[PulseMonitoringToken] {
		return "", errors.New("HOLD: exact stale Pulse monitoring token remains after deletion")
	}
	return CreatePulseMonitoringCredentials(ctx, runner, address, initialUser)
}

type pulseMonitoringUserEntry struct {
	Comment string `json:"comment"`
	Enable  int    `json:"enable"`
	Expire  int    `json:"expire"`
	UserID  string `json:"userid"`
}

type pulseMonitoringTokenEntry struct {
	Expire  int    `json:"expire"`
	Privsep int    `json:"privsep"`
	TokenID string `json:"tokenid"`
}

type pulseMonitoringACLEntry struct {
	Path      string `json:"path"`
	Propagate int    `json:"propagate"`
	RoleID    string `json:"roleid"`
	Type      string `json:"type"`
	UGID      string `json:"ugid"`
}

func validatePulseMonitoringUserOwnership(usersOutput []byte) error {
	var users []pulseMonitoringUserEntry
	if err := decodeAccessList(usersOutput, &users); err != nil {
		return fmt.Errorf("decode Pulse monitoring users: %w", err)
	}
	userFound := false
	for _, user := range users {
		if user.UserID != PulseMonitoringUser {
			continue
		}
		if user.Comment != "Pulse API-only monitoring identity" || user.Enable != 1 || user.Expire != 0 {
			return errors.New("Pulse monitoring user metadata is unexpected")
		}
		userFound = true
	}
	if !userFound {
		return errors.New("Pulse monitoring user is absent")
	}
	return nil
}

func validatePulseMonitoringTokenOwnership(usersOutput, tokensOutput, aclOutput []byte) error {
	if err := validatePulseMonitoringUserOwnership(usersOutput); err != nil {
		return err
	}
	var tokens []pulseMonitoringTokenEntry
	if err := decodeAccessList(tokensOutput, &tokens); err != nil {
		return fmt.Errorf("decode Pulse monitoring tokens: %w", err)
	}
	tokenFound := false
	for _, token := range tokens {
		if token.TokenID != PulseMonitoringToken {
			continue
		}
		if token.Privsep != 1 || token.Expire != 0 {
			return errors.New("Pulse monitoring token metadata is unexpected")
		}
		tokenFound = true
	}
	if !tokenFound {
		return errors.New("Pulse monitoring token is absent")
	}
	var acls []pulseMonitoringACLEntry
	if err := decodeAccessList(aclOutput, &acls); err != nil {
		return fmt.Errorf("decode Pulse monitoring ACLs: %w", err)
	}
	expected := map[string]string{
		PulseMonitoringUser: "user",
		PulseMonitoringUser + "!" + PulseMonitoringToken: "token",
	}
	seen := make(map[string]bool, len(expected))
	for _, acl := range acls {
		expectedType, relevant := expected[acl.UGID]
		if !relevant {
			continue
		}
		if seen[acl.UGID] || acl.Path != "/" || acl.Propagate != 1 || acl.RoleID != PulseMonitoringRole || acl.Type != expectedType {
			return errors.New("Pulse monitoring ACL is unexpected")
		}
		seen[acl.UGID] = true
	}
	for ugid := range expected {
		if !seen[ugid] {
			return fmt.Errorf("Pulse monitoring ACL %q is absent", ugid)
		}
	}
	return nil
}

func decodeAccessList(output []byte, destination any) error {
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(output, &envelope); err == nil && len(envelope.Data) > 0 {
		return json.Unmarshal(envelope.Data, destination)
	}
	return json.Unmarshal(output, destination)
}

type scopedCredentialUserEntry struct {
	Comment string `json:"comment"`
	Enable  int    `json:"enable"`
	Expire  int    `json:"expire"`
	UserID  string `json:"userid"`
}

type scopedCredentialTokenEntry struct {
	Expire  int    `json:"expire"`
	Privsep int    `json:"privsep"`
	TokenID string `json:"tokenid"`
}

type scopedCredentialACLEntry struct {
	Path      string `json:"path"`
	Propagate int    `json:"propagate"`
	RoleID    string `json:"roleid"`
	Type      string `json:"type"`
	UGID      string `json:"ugid"`
}

func validateScopedCredentialTokenOwnership(usersOutput, tokensOutput, aclOutput []byte, userID, tokenID, role, node string) error {
	if err := validateScopedCredentialUserOwnership(usersOutput, userID); err != nil {
		return err
	}
	if err := validateScopedCredentialTokenMetadata(tokensOutput, tokenID); err != nil {
		return err
	}

	var acls []scopedCredentialACLEntry
	if err := decodeAccessList(aclOutput, &acls); err != nil {
		return fmt.Errorf("decode scoped credential ACLs: %w", err)
	}
	expected := map[string]string{
		userID:                 "user",
		userID + "!" + tokenID: "token",
	}
	paths := scopedProvisionerACLPaths(node)
	if len(paths) == 0 {
		return errors.New("scoped credential ACL node is malformed")
	}
	allowedPaths := make(map[string]bool, len(paths))
	for _, path := range paths {
		allowedPaths[path] = true
	}
	seenLegacy := make(map[string]bool, len(expected))
	seenScoped := make(map[string]bool, len(expected)*len(allowedPaths))
	for _, acl := range acls {
		expectedType, relevant := expected[acl.UGID]
		if !relevant {
			continue
		}
		if acl.Propagate != 1 || acl.RoleID != role || acl.Type != expectedType {
			return errors.New("scoped credential ACL is unexpected")
		}
		if acl.Path == "/" {
			if seenLegacy[acl.UGID] || len(seenScoped) > 0 {
				return errors.New("scoped credential ACL is unexpected")
			}
			seenLegacy[acl.UGID] = true
			continue
		}
		if !allowedPaths[acl.Path] || seenLegacy[acl.UGID] {
			return errors.New("scoped credential ACL is unexpected")
		}
		key := acl.UGID + "\x00" + acl.Path
		if seenScoped[key] {
			return errors.New("scoped credential ACL is unexpected")
		}
		seenScoped[key] = true
	}
	if len(seenLegacy) > 0 {
		if len(seenLegacy) != len(expected) {
			return errors.New("scoped credential ACL is incomplete")
		}
		return nil
	}
	for ugid := range expected {
		for _, path := range paths {
			if !seenScoped[ugid+"\x00"+path] {
				return fmt.Errorf("scoped credential ACL %q at %s is absent", ugid, path)
			}
		}
	}
	return nil
}

func validateScopedCredentialUserOwnership(output []byte, userID string) error {
	var users []scopedCredentialUserEntry
	if err := decodeAccessList(output, &users); err != nil {
		return fmt.Errorf("decode scoped credential users: %w", err)
	}
	for _, user := range users {
		if user.UserID != userID {
			continue
		}
		if user.Comment != scopedCredentialComment || user.Enable != 1 || user.Expire != 0 {
			return errors.New("scoped credential user metadata is unexpected")
		}
		return nil
	}
	return errors.New("scoped credential user is absent")
}

func validateScopedCredentialTokenMetadata(output []byte, tokenID string) error {
	var tokens []scopedCredentialTokenEntry
	if err := decodeAccessList(output, &tokens); err != nil {
		return fmt.Errorf("decode scoped credential tokens: %w", err)
	}
	for _, token := range tokens {
		if token.TokenID != tokenID {
			continue
		}
		if token.Privsep != 1 || token.Expire != 0 {
			return errors.New("scoped credential token metadata is unexpected")
		}
		return nil
	}
	return errors.New("scoped credential token is absent")
}

func requireBuiltInRole(output []byte, wanted, wantedPrivileges string) error {
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
		if canonicalPrivileges(entry.Privileges) != canonicalPrivileges(wantedPrivileges) {
			return fmt.Errorf("privileges %q do not match required set %q", entry.Privileges, wantedPrivileges)
		}
		return nil
	}
	return errors.New("role is not present")
}

func CreateScopedCredentialsWithRole(ctx context.Context, runner CommandRunner, address, initialUser, userID, tokenID, role, node string) (string, error) {
	if !safeID(userID) || !safeID(tokenID) || !safeID(role) {
		return "", errors.New("Proxmox identity and token IDs must be simple identifiers")
	}
	aclPaths := scopedProvisionerACLPaths(node)
	if len(aclPaths) == 0 {
		return "", errors.New("Proxmox node identifier is required and must be safe for scoped ACLs")
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
		createUser := "pvesh create /access/users --userid " + shellQuote(userID) + " --comment " + shellQuote(scopedCredentialComment)
		if _, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, createUser)); err != nil {
			return "", fmt.Errorf("create Proxmox automation user: %w", err)
		}
	} else if err := validateScopedCredentialUserOwnership(usersOutput, userID); err != nil {
		return "", fmt.Errorf("HOLD: existing Proxmox user %s is not the expected Boetticher identity: %w", userID, err)
	}
	if err := setScopedCredentialACL(ctx, runner, address, initialUser, "--users", userID, role, aclPaths); err != nil {
		return "", fmt.Errorf("assign bounded Proxmox role to user: %w", err)
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
	if err := setScopedCredentialACL(ctx, runner, address, initialUser, "--tokens", userID+"!"+tokenID, role, aclPaths); err != nil {
		return "", fmt.Errorf("assign bounded Proxmox role to token: %w", err)
	}
	return response.Value, nil
}

// EnsureScopedCredentialACL repairs the bounded user and token ACLs for an
// existing privilege-separated provisioning identity. Proxmox restricts a
// token to the permissions of its backing user, so both ACLs are required.
func EnsureScopedCredentialACL(ctx context.Context, runner CommandRunner, address, initialUser, userID, tokenID, role, node string) error {
	if !safeID(userID) || !safeID(tokenID) || !safeID(role) {
		return errors.New("Proxmox identity and token IDs must be simple identifiers")
	}
	aclPaths := scopedProvisionerACLPaths(node)
	if len(aclPaths) == 0 {
		return errors.New("Proxmox node identifier is required and must be safe for scoped ACLs")
	}
	roleOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, "pvesh get /access/roles --output-format json"))
	if err != nil {
		return fmt.Errorf("inspect scoped Proxmox role: %w", err)
	}
	if exists, roleErr := validateScopedRoleJSON(roleOutput, role, ScopedProvisionerPrivileges()); roleErr != nil || !exists {
		if roleErr != nil {
			return fmt.Errorf("validate scoped Proxmox role: %w", roleErr)
		}
		return fmt.Errorf("validate scoped Proxmox role: role %q is absent", role)
	}
	usersOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, "pvesh get /access/users --output-format json"))
	if err != nil {
		return fmt.Errorf("inspect scoped Proxmox user: %w", err)
	}
	if err := validateScopedCredentialUserOwnership(usersOutput, userID); err != nil {
		return fmt.Errorf("validate scoped Proxmox user: %w", err)
	}
	tokensOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, "pvesh get /access/users/"+shellQuote(userID)+"/token --output-format json"))
	if err != nil {
		return fmt.Errorf("inspect scoped Proxmox token: %w", err)
	}
	if err := validateScopedCredentialTokenMetadata(tokensOutput, tokenID); err != nil {
		return fmt.Errorf("validate scoped Proxmox token: %w", err)
	}
	aclOutput, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, "pvesh get /access/acl --output-format json"))
	if err != nil {
		return fmt.Errorf("inspect existing scoped Proxmox ACLs: %w", err)
	}
	if err := removeLegacyScopedCredentialACLs(ctx, runner, address, initialUser, aclOutput, userID, tokenID, role); err != nil {
		return fmt.Errorf("remove legacy root ACLs: %w", err)
	}
	if err := setScopedCredentialACL(ctx, runner, address, initialUser, "--users", userID, role, aclPaths); err != nil {
		return fmt.Errorf("assign bounded Proxmox role to user: %w", err)
	}
	if err := setScopedCredentialACL(ctx, runner, address, initialUser, "--tokens", userID+"!"+tokenID, role, aclPaths); err != nil {
		return fmt.Errorf("assign bounded Proxmox role to token: %w", err)
	}
	updatedACL, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, "pvesh get /access/acl --output-format json"))
	if err != nil {
		return fmt.Errorf("verify scoped Proxmox ACLs: %w", err)
	}
	if err := validateScopedProvisionerACL(updatedACL, userID, tokenID, role, node); err != nil {
		return fmt.Errorf("verify scoped Proxmox ACLs: %w", err)
	}
	return nil
}

func setScopedCredentialACL(ctx context.Context, runner CommandRunner, address, initialUser, subjectFlag, subject, role string, paths []string) error {
	for _, aclPath := range paths {
		setACL := "pvesh set /access/acl --path " + shellQuote(aclPath) + " " + subjectFlag + " " + shellQuote(subject) + " --roles " + shellQuote(role) + " --propagate 1"
		if _, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, setACL)); err != nil {
			return err
		}
	}
	return nil
}

func scopedProvisionerACLPaths(node string) []string {
	if !safeNodeID(node) {
		return nil
	}
	paths := []string{"/nodes/" + node, "/sdn", "/storage/local", "/storage/boetticher-thin", "/storage/boetticher-backups"}
	for _, vmid := range []int{model.ProxmoxVMID, model.DNS01VMID, model.MonitorVMID, model.LoggingVMID, model.LegacyStreamDeckVMID, model.PrinterVMID, model.AirVPNGuestVMID, model.ArrVMID, 200, 210, 240, 250} {
		paths = append(paths, "/vms/"+strconv.Itoa(vmid))
	}
	return paths
}

func removeLegacyScopedCredentialACLs(ctx context.Context, runner CommandRunner, address, initialUser string, aclOutput []byte, userID, tokenID, role string) error {
	var acls []scopedCredentialACLEntry
	if err := decodeAccessList(aclOutput, &acls); err != nil {
		return fmt.Errorf("decode ACL listing: %w", err)
	}
	for _, subject := range []struct {
		flag  string
		value string
		typ   string
	}{{"--users", userID, "user"}, {"--tokens", userID + "!" + tokenID, "token"}} {
		found := false
		for _, acl := range acls {
			if acl.UGID == subject.value && acl.Type == subject.typ && acl.Path == "/" && acl.Propagate == 1 && acl.RoleID == role {
				found = true
				break
			}
		}
		if !found {
			continue
		}
		command := "pvesh delete /access/acl --path / " + subject.flag + " " + shellQuote(subject.value) + " --roles " + shellQuote(role)
		if _, err := runner.Run(ctx, address, initialUser, privilegedCommand(initialUser, command)); err != nil {
			return fmt.Errorf("remove root %s ACL: %w", subject.typ, err)
		}
	}
	return nil
}

func validateScopedProvisionerACL(aclOutput []byte, userID, tokenID, role, node string) error {
	var acls []scopedCredentialACLEntry
	if err := decodeAccessList(aclOutput, &acls); err != nil {
		return fmt.Errorf("decode ACL listing: %w", err)
	}
	expected := map[string]string{userID: "user", userID + "!" + tokenID: "token"}
	paths := scopedProvisionerACLPaths(node)
	if len(paths) == 0 {
		return errors.New("scoped credential ACL node is malformed")
	}
	allowedPaths := make(map[string]bool, len(paths))
	for _, path := range paths {
		allowedPaths[path] = true
	}
	seen := make(map[string]bool, len(expected)*len(allowedPaths))
	for _, acl := range acls {
		expectedType, relevant := expected[acl.UGID]
		if !relevant {
			continue
		}
		if acl.Path == "/" || !allowedPaths[acl.Path] || acl.Propagate != 1 || acl.RoleID != role || acl.Type != expectedType {
			return errors.New("scoped credential ACL is unexpected")
		}
		key := acl.UGID + "\x00" + acl.Path
		if seen[key] {
			return errors.New("scoped credential ACL is duplicated")
		}
		seen[key] = true
	}
	for ugid := range expected {
		for _, path := range paths {
			if !seen[ugid+"\x00"+path] {
				return fmt.Errorf("scoped credential ACL %q at %s is absent", ugid, path)
			}
		}
	}
	return nil
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
