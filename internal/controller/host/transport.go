package host

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/gofastercloud/boetticher/internal/pathguard"
)

const maxSSHOutput = 1 << 20

type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

type Transport struct {
	Address    string
	User       string
	Identity   string
	KnownHosts string
	Timeout    time.Duration
	SSHPath    string
}

func (t Transport) Args(command string) ([]string, error) {
	ip := net.ParseIP(t.Address)
	if ip == nil || ip.To4() == nil {
		return nil, errors.New("Proxmox address must be an IPv4 address")
	}
	if t.User != "root" {
		return nil, errors.New("Proxmox transport requires root")
	}
	if t.Identity == "" || t.KnownHosts == "" || command == "" {
		return nil, errors.New("Proxmox transport identity, known-hosts, and command are required")
	}
	if err := pathguard.ValidateNoSymlinkComponents(t.Identity); err != nil {
		return nil, fmt.Errorf("validate Proxmox identity path: %w", err)
	}
	if err := pathguard.ValidateNoSymlinkComponents(t.KnownHosts); err != nil {
		return nil, fmt.Errorf("validate Proxmox known-hosts path: %w", err)
	}
	return []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + t.KnownHosts,
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityFile=" + t.Identity,
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
		"-o", "ForwardAgent=no",
		"-o", "ForwardX11=no",
		"-o", "RequestTTY=no",
		t.User + "@" + t.Address,
		command,
	}, nil
}

// SCPArgs returns the same strict Host identity binding as Args for the one
// Controller bootstrap path that streams a verified local appliance artifact.
// It does not expose a general remote-copy workflow to operators.
func (t Transport) SCPArgs(source, destination string) ([]string, error) {
	ip := net.ParseIP(t.Address)
	if ip == nil || ip.To4() == nil {
		return nil, errors.New("Proxmox address must be an IPv4 address")
	}
	if t.User != "root" {
		return nil, errors.New("Proxmox transport requires root")
	}
	if t.Identity == "" || t.KnownHosts == "" || source == "" || destination == "" || strings.ContainsAny(source+destination, "\r\n\x00") {
		return nil, errors.New("Proxmox copy identity, known-hosts, source, and destination are required")
	}
	if err := pathguard.ValidateNoSymlinkComponents(t.Identity); err != nil {
		return nil, fmt.Errorf("validate Proxmox identity path: %w", err)
	}
	if err := pathguard.ValidateNoSymlinkComponents(t.KnownHosts); err != nil {
		return nil, fmt.Errorf("validate Proxmox known-hosts path: %w", err)
	}
	return []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + t.KnownHosts,
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityFile=" + t.Identity,
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
		"-o", "ForwardAgent=no",
		"-o", "ForwardX11=no",
		source,
		t.User + "@" + t.Address + ":" + destination,
	}, nil
}

// SCPFromArgs is the strict reverse copy used when the x86 Host builds a
// provider image for an ARM64 Controller. The remote source and local
// destination are fixed by the capability caller; this is not an operator
// file-transfer workflow.
func (t Transport) SCPFromArgs(source, destination string) ([]string, error) {
	ip := net.ParseIP(t.Address)
	if ip == nil || ip.To4() == nil {
		return nil, errors.New("Proxmox address must be an IPv4 address")
	}
	if t.User != "root" {
		return nil, errors.New("Proxmox transport requires root")
	}
	if t.Identity == "" || t.KnownHosts == "" || source == "" || destination == "" || strings.ContainsAny(source+destination, "\r\n\x00") {
		return nil, errors.New("Proxmox reverse copy identity, known-hosts, source, and destination are required")
	}
	if err := pathguard.ValidateNoSymlinkComponents(t.Identity); err != nil {
		return nil, fmt.Errorf("validate Proxmox identity path: %w", err)
	}
	if err := pathguard.ValidateNoSymlinkComponents(t.KnownHosts); err != nil {
		return nil, fmt.Errorf("validate Proxmox known-hosts path: %w", err)
	}
	if err := pathguard.ValidateNoSymlinkComponents(destination); err != nil {
		return nil, fmt.Errorf("validate local copy destination: %w", err)
	}
	return []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + t.KnownHosts,
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityFile=" + t.Identity,
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
		"-o", "ForwardAgent=no",
		"-o", "ForwardX11=no",
		t.User + "@" + t.Address + ":" + source,
		destination,
	}, nil
}

func (t Transport) Run(ctx context.Context, command string) (Result, error) {
	return t.run(ctx, command, nil)
}

// RunWithStdin keeps sensitive build input out of argv, logs, and remote
// temporary files while using the same strict SSH route as Run.
func (t Transport) RunWithStdin(ctx context.Context, command string, stdin io.Reader) (Result, error) {
	return t.run(ctx, command, stdin)
}

func (t Transport) run(ctx context.Context, command string, stdin io.Reader) (Result, error) {
	process, commandContext, cancel, err := t.command(ctx, command)
	if err != nil {
		return Result{}, err
	}
	defer cancel()
	process.Stdin = stdin
	var stdout, stderr boundedBuffer
	process.Stdout = &stdout
	process.Stderr = &stderr
	err = process.Run()
	return finishRun(commandContext, Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, err)
}

// RunLines is the line-streaming variant of Run for bounded helpers that
// report progress while they work. Each complete stdout line is passed to
// onLine as it arrives (the slice is only valid during the call); stdout is
// not retained in the Result. A line longer than maxLine is a protocol
// failure: the session is terminated and an error returned. The SSH options,
// identity binding, and timeout are identical to Run.
func (t Transport) RunLines(ctx context.Context, command string, maxLine int, onLine func([]byte)) (Result, error) {
	if maxLine <= 0 || onLine == nil {
		return Result{}, errors.New("Proxmox streaming command requires a line bound and handler")
	}
	process, commandContext, cancel, err := t.command(ctx, command)
	if err != nil {
		return Result{}, err
	}
	defer cancel()
	// Stdout is read before Wait, so cancellation must close the pipe by
	// ending the whole SSH process group rather than only the direct child.
	process.Cancel = func() error { return syscall.Kill(-process.Process.Pid, syscall.SIGKILL) }
	process.WaitDelay = 5 * time.Second
	var stderr boundedBuffer
	process.Stderr = &stderr
	stdout, err := process.StdoutPipe()
	if err != nil {
		return Result{}, err
	}
	if err := process.Start(); err != nil {
		return Result{}, fmt.Errorf("start Proxmox SSH command: %w", err)
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, min(maxLine, 64*1024)), maxLine)
	for scanner.Scan() {
		onLine(scanner.Bytes())
	}
	scanErr := scanner.Err()
	if scanErr != nil {
		cancel()
		_, _ = io.Copy(io.Discard, stdout)
	}
	err = process.Wait()
	result := Result{Stderr: stderr.Bytes()}
	if scanErr != nil {
		result.ExitCode = 1
		return result, fmt.Errorf("Proxmox SSH command output: %w", scanErr)
	}
	return finishRun(commandContext, result, err)
}

func (t Transport) command(ctx context.Context, command string) (*exec.Cmd, context.Context, context.CancelFunc, error) {
	args, err := t.Args(command)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, err
	}
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	commandContext, cancel := context.WithTimeout(ctx, timeout)
	sshPath := t.SSHPath
	if sshPath == "" {
		sshPath = "/usr/bin/ssh"
	}
	process := exec.CommandContext(commandContext, sshPath, args...)
	process.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return process, commandContext, cancel, nil
}

func finishRun(commandContext context.Context, result Result, err error) (Result, error) {
	if err == nil {
		return result, nil
	}
	result.ExitCode = 1
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
	}
	if errors.Is(commandContext.Err(), context.DeadlineExceeded) {
		return result, fmt.Errorf("Proxmox SSH command timed out: %w", commandContext.Err())
	}
	detail := strings.TrimSpace(string(result.Stderr))
	if detail != "" {
		return result, fmt.Errorf("Proxmox SSH command failed: %w: %s", err, detail)
	}
	return result, fmt.Errorf("Proxmox SSH command failed: %w", err)
}

type boundedBuffer struct{ data []byte }

func (b *boundedBuffer) Write(data []byte) (int, error) {
	remaining := maxSSHOutput - len(b.data)
	if remaining > 0 {
		if len(data) > remaining {
			b.data = append(b.data, data[:remaining]...)
		} else {
			b.data = append(b.data, data...)
		}
	}
	return len(data), nil
}

func (b *boundedBuffer) Bytes() []byte { return bytes.Clone(b.data) }
