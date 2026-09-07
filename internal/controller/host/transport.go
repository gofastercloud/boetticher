package host

import (
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
	args, err := t.Args(command)
	if err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	commandContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	sshPath := t.SSHPath
	if sshPath == "" {
		sshPath = "/usr/bin/ssh"
	}
	process := exec.CommandContext(commandContext, sshPath, args...)
	process.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	process.Stdin = stdin
	var stdout, stderr boundedBuffer
	process.Stdout = &stdout
	process.Stderr = &stderr
	err = process.Run()
	result := Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: 0}
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
