package host

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gofastercloud/boetticher/internal/firewalltest"
)

const (
	installRoot    = "/opt/boetticher"
	currentRelease = installRoot + "/current"
	ansibleVenv    = installRoot + "/venv/bin/ansible-playbook"
)

func ResolveProxmoxRuntime() (string, error) {
	runtime, err := filepath.EvalSymlinks(currentRelease)
	if err != nil {
		return "", fmt.Errorf("resolve controller runtime: %w", err)
	}
	releases, err := filepath.EvalSymlinks(filepath.Join(installRoot, "releases"))
	if err != nil {
		return "", fmt.Errorf("resolve controller releases: %w", err)
	}
	rel, err := filepath.Rel(releases, runtime)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", errors.New("controller runtime is outside the versioned release directory")
	}
	playbook := filepath.Join(runtime, "controller", "proxmox", "prepare.yml")
	if info, err := os.Stat(playbook); err != nil || !info.Mode().IsRegular() {
		return "", errors.New("installed controller does not contain the Proxmox preparation playbook")
	}
	return runtime, nil
}

func CheckBaseline(ctx context.Context, transport Transport) (bool, error) {
	result, err := transport.Run(ctx, "set -eu; test -f /etc/apt/sources.list.d/boetticher-pve-no-subscription.sources; test -f /etc/systemd/logind.conf.d/90-boetticher-headless.conf; dpkg-query -W -f='${Status}' rsync 2>/dev/null | grep -qx 'install ok installed'; for command in arping bash bzip2 dig diff dhclient file find gawk gzip make patch perl python3 tar unzip wget which xz zstd; do command -v \"$command\" >/dev/null; done; test -x /usr/local/libexec/boetticher-host-speedtest; test -x /usr/local/libexec/boetticher-firewall-test-host; test \"$(/usr/local/libexec/boetticher-firewall-test-host --version)\" = "+firewalltest.HelperVersion)
	if err != nil {
		return false, nil
	}
	return result.ExitCode == 0, nil
}

func RunPrepare(ctx context.Context, config LabConfig, transport Transport, out io.Writer) error {
	if out == nil {
		return errors.New("preparation output is required")
	}
	runtime, err := ResolveProxmoxRuntime()
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp("", "boetticher-proxmox-inventory-")
	if err != nil {
		return fmt.Errorf("create temporary Proxmox inventory: %w", err)
	}
	path := temporary.Name()
	defer os.Remove(path)
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return err
	}
	content := fmt.Sprintf("[proxmox]\nlab-proxmox ansible_host=%s ansible_user=root\n\n[proxmox:vars]\nansible_ssh_private_key_file=%s\nansible_ssh_common_args=-o UserKnownHostsFile=%s -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o ControlMaster=no -o ControlPath=none -o RequestTTY=no\n", config.Proxmox.Address, PrivateKeyPath, KnownHostsPath)
	if _, err := temporary.WriteString(content); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary Proxmox inventory: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary Proxmox inventory: %w", err)
	}
	playbookDir := filepath.Join(runtime, "controller", "proxmox")
	commandContext, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	command := exec.CommandContext(commandContext, ansibleVenv, "-i", path, filepath.Join(playbookDir, "prepare.yml"))
	command.Dir = playbookDir
	command.Env = cleanAnsibleEnvironment(runtime)
	var ansibleOutput bytes.Buffer
	command.Stdout = &ansibleOutput
	command.Stderr = &ansibleOutput
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Run(); err != nil {
		appendOperationLog("host prepare", ansibleOutput.String())
		if errors.Is(commandContext.Err(), context.DeadlineExceeded) {
			return errors.New("Proxmox host preparation timed out")
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			return fmt.Errorf("Proxmox host preparation interrupted: %w", ctx.Err())
		}
		detail := strings.TrimSpace(ansibleOutput.String())
		if detail == "" {
			return fmt.Errorf("Proxmox host preparation failed: %w", err)
		}
		lines := strings.Split(detail, "\n")
		if len(lines) > 12 {
			lines = lines[len(lines)-12:]
		}
		return fmt.Errorf("Proxmox host preparation failed: %w: %s", err, strings.Join(lines, " "))
	}
	appendOperationLog("host prepare", ansibleOutput.String())
	return nil
}

func appendOperationLog(operation, output string) {
	if strings.TrimSpace(output) == "" {
		return
	}
	const maxOperationLogOutput = 64 << 10
	if len(output) > maxOperationLogOutput {
		output = output[len(output)-maxOperationLogOutput:]
	}
	file, err := os.OpenFile("/var/log/boetticher/operations.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	defer file.Close()
	_, _ = fmt.Fprintf(file, "[%s] %s\n", time.Now().UTC().Format(time.RFC3339), operation)
	_, _ = file.WriteString(output + "\n")
}

func cleanAnsibleEnvironment(runtime string) []string {
	env := make([]string, 0, len(os.Environ())+4)
	for _, value := range os.Environ() {
		if strings.HasPrefix(value, "ANSIBLE_") || strings.HasPrefix(value, "PYTHONPATH=") {
			continue
		}
		env = append(env, value)
	}
	return append(env,
		"ANSIBLE_CONFIG="+filepath.Join(runtime, "controller", "proxmox", "ansible.cfg"),
		"ANSIBLE_NOCOLOR=1",
		"PYTHONNOUSERSITE=1",
		"LC_ALL=C.UTF-8",
	)
}
