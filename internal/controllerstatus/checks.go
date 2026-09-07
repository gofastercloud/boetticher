package controllerstatus

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"gopkg.in/yaml.v3"
)

type CheckResult struct {
	Configured bool
	Healthy    bool
	Update     Component
	Detail     string
}

type CommandRunner func(context.Context, string, ...string) ([]byte, error)

func defaultCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

type ControllerChecker struct {
	ConfigPath         string
	UpdateConfigPath   string
	RebootRequiredPath string
	RequiredServices   []string
	RootPath           string
	RunCommand         CommandRunner
	Statfs             func(string, *syscall.Statfs_t) error
}

func (c ControllerChecker) Check(ctx context.Context) CheckResult {
	path := c.ConfigPath
	if path == "" {
		path = DefaultConfigPath
	}
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
		return CheckResult{Configured: true, Detail: "Controller configuration cannot be read"}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return CheckResult{Configured: true, Detail: "Controller configuration cannot be read"}
	}
	var config struct {
		OperatorUser string `yaml:"operator_user"`
	}
	if err := yaml.Unmarshal(data, &config); err != nil || config.OperatorUser == "" {
		return CheckResult{Configured: true, Detail: "Controller configuration is invalid"}
	}
	run := c.RunCommand
	if run == nil {
		run = defaultCommand
	}
	services := c.RequiredServices
	if len(services) == 0 {
		services = []string{"systemd-journald.service", "ssh.service", "boetticher-status.service"}
	}
	for _, service := range services {
		if _, err := run(ctx, "systemctl", "is-active", "--quiet", service); err != nil {
			return CheckResult{Configured: true, Detail: service + " is not active"}
		}
	}
	updateConfigPath := c.UpdateConfigPath
	if updateConfigPath == "" {
		updateConfigPath = "/etc/apt/apt.conf.d/52boetticher-unattended"
	}
	aptConfig, err := os.ReadFile(updateConfigPath)
	if err != nil || !strings.Contains(string(aptConfig), `APT::Periodic::Unattended-Upgrade "1";`) || !strings.Contains(string(aptConfig), `Unattended-Upgrade::Automatic-Reboot "false";`) {
		return CheckResult{Configured: true, Update: Component{State: Attention, Detail: "unattended security updates are not configured"}, Detail: "unattended security updates are not configured"}
	}
	for _, timer := range []string{"apt-daily.timer", "apt-daily-upgrade.timer"} {
		if _, err := run(ctx, "systemctl", "is-active", "--quiet", timer); err != nil {
			return CheckResult{Configured: true, Update: Component{State: Attention, Detail: "automatic security-update timers are not active"}, Detail: "automatic security-update timers are not active"}
		}
	}
	root := c.RootPath
	if root == "" {
		root = "/"
	}
	statfs := c.Statfs
	if statfs == nil {
		statfs = syscall.Statfs
	}
	var info syscall.Statfs_t
	if err := statfs(root, &info); err != nil {
		return CheckResult{Configured: true, Detail: "root filesystem cannot be inspected"}
	}
	available := uint64(info.Bavail) * uint64(info.Bsize)
	if available < 1<<30 {
		return CheckResult{Configured: true, Detail: "root filesystem has less than 1 GiB available"}
	}
	return CheckResult{Configured: true, Healthy: true, Update: controllerUpdateStatus(ctx, run, c.RebootRequiredPath), Detail: "configuration, required services, and root filesystem are healthy"}
}

func controllerUpdateStatus(ctx context.Context, run CommandRunner, rebootPath string) Component {
	if RebootResult(rebootPath).State == Attention {
		return Component{State: Attention, Detail: "Controller reboot required"}
	}
	output, err := run(ctx, "apt", "list", "--upgradable")
	if err != nil {
		return Component{State: Attention, Detail: "Controller update state cannot be inspected"}
	}
	if packages := packageNames(output, func(name string) bool { return name != "" }); len(packages) > 0 {
		return Component{State: Attention, Detail: fmt.Sprintf("Controller updates available (%d)", len(packages))}
	}
	return Component{State: Healthy, Detail: "No Controller updates available"}
}

func packageNames(output []byte, include func(string) bool) []string {
	var packages []string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "Listing..." {
			continue
		}
		name := strings.SplitN(line, "/", 2)[0]
		if include(name) {
			packages = append(packages, name)
		}
	}
	return packages
}

type HostChecker struct {
	LoadConfig func() (controllerhost.LabConfig, error)
	Transport  func(controllerhost.LabConfig) (controllerhost.Transport, error)
	Run        func(context.Context, controllerhost.Transport, string) (controllerhost.Result, error)
}

type HostConnectivityChecker struct {
	LoadConfig func() (controllerhost.LabConfig, error)
	Transport  func(controllerhost.LabConfig) (controllerhost.Transport, error)
	Run        func(context.Context, controllerhost.Transport, string) (controllerhost.Result, error)
}

type HostSpeedtestChecker struct {
	LoadConfig func() (controllerhost.LabConfig, error)
	Transport  func(controllerhost.LabConfig) (controllerhost.Transport, error)
	Run        func(context.Context, controllerhost.Transport, string) (controllerhost.Result, error)
}

func (c HostChecker) Check(ctx context.Context) CheckResult {
	load := c.LoadConfig
	if load == nil {
		load = controllerhost.LoadConfig
	}
	config, err := load()
	if errors.Is(err, os.ErrNotExist) {
		return CheckResult{Detail: "Host not enrolled"}
	}
	if err != nil {
		return CheckResult{Configured: true, Detail: "Host configuration cannot be read"}
	}
	if config.Proxmox.Node == "" {
		return CheckResult{Detail: "Host not enrolled"}
	}
	transportFor := c.Transport
	if transportFor == nil {
		transportFor = controllerhost.TransportFor
	}
	transport, err := transportFor(config)
	if err != nil {
		return CheckResult{Configured: true, Detail: "Host transport configuration is invalid"}
	}
	transport.Timeout = 5 * time.Second
	command := hostHealthCommand(config)
	run := c.Run
	if run == nil {
		run = func(ctx context.Context, transport controllerhost.Transport, command string) (controllerhost.Result, error) {
			return transport.Run(ctx, command)
		}
	}
	result, err := run(ctx, transport, command)
	update := hostUpdateStatus(result.Stdout)
	if err != nil {
		return CheckResult{Configured: true, Update: update, Detail: "enrolled Host health check failed"}
	}
	return CheckResult{Configured: true, Healthy: true, Update: update, Detail: "enrolled Host fundamentals are healthy"}
}

func (c HostConnectivityChecker) Check(ctx context.Context) CheckResult {
	load := c.LoadConfig
	if load == nil {
		load = controllerhost.LoadConfig
	}
	config, err := load()
	if errors.Is(err, os.ErrNotExist) || (err == nil && config.Proxmox.Node == "") {
		return CheckInternet(ctx, nil)
	}
	if err != nil {
		return CheckResult{Configured: true, Detail: "Host configuration cannot be read"}
	}
	transportFor := c.Transport
	if transportFor == nil {
		transportFor = controllerhost.TransportFor
	}
	transport, err := transportFor(config)
	if err != nil {
		return CheckResult{Configured: true, Detail: "Host transport configuration is invalid"}
	}
	transport.Timeout = 5 * time.Second
	run := c.Run
	if run == nil {
		run = func(ctx context.Context, transport controllerhost.Transport, command string) (controllerhost.Result, error) {
			return transport.Run(ctx, command)
		}
	}
	if _, err := run(ctx, transport, "set -eu; ping -n -c 1 -W 3 1.1.1.1 >/dev/null 2>&1 || curl --fail --silent --show-error --max-time 3 --output /dev/null https://speed.cloudflare.com/__down?bytes=0"); err != nil {
		return CheckResult{Configured: true, Detail: "Host Internet connectivity check failed"}
	}
	return CheckResult{Configured: true, Healthy: true, Detail: "Host Internet connectivity is available"}
}

func (c HostSpeedtestChecker) Sample(ctx context.Context) (float64, error) {
	load := c.LoadConfig
	if load == nil {
		load = controllerhost.LoadConfig
	}
	config, err := load()
	if errors.Is(err, os.ErrNotExist) {
		return 0, errors.New("Host not enrolled")
	}
	if err != nil {
		return 0, fmt.Errorf("read Host configuration: %w", err)
	}
	if config.Proxmox.Node == "" {
		return 0, errors.New("Host not enrolled")
	}
	transportFor := c.Transport
	if transportFor == nil {
		transportFor = controllerhost.TransportFor
	}
	transport, err := transportFor(config)
	if err != nil {
		return 0, err
	}
	transport.Timeout = 3 * time.Minute
	command := DefaultHostSpeedtestPath + " --source vmbr0 --json"
	run := c.Run
	if run == nil {
		run = func(ctx context.Context, transport controllerhost.Transport, command string) (controllerhost.Result, error) {
			return transport.Run(ctx, command)
		}
	}
	result, err := run(ctx, transport, command)
	if err != nil {
		return 0, fmt.Errorf("Host throughput sample failed: %w", err)
	}
	var samples []struct {
		Download float64 `json:"download_mbps"`
	}
	if err := json.Unmarshal(result.Stdout, &samples); err != nil || len(samples) == 0 || samples[0].Download <= 0 {
		return 0, errors.New("Host speedtest returned no usable download result")
	}
	return samples[0].Download, nil
}

func hostHealthCommand(config controllerhost.LabConfig) string {
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
	checks := []string{
		"test \"$(hostname)\" = " + quote(config.Proxmox.Node),
		"for service in pve-cluster pvedaemon pvestatd pveproxy; do systemctl is-active --quiet \"$service\"; done",
		"ip -json address show | grep -Fq " + quote(config.Proxmox.Address),
	}
	if config.Storage != nil {
		storage := quote(config.Storage.GuestStorage)
		checks = append(checks, "pvesm status --storage "+storage+" | awk -v expected="+storage+" 'NR > 1 && $1 == expected && $3 == \"active\" { found=1 } END { exit found ? 0 : 1 }'")
	}
	if config.Network != nil {
		checks = append(checks,
			"ip -d link show vmbr1 | grep -Eq 'vlan_filtering (1|on)'",
			"test -z \"$(bridge link | awk '$NF == \\\"vmbr1\\\" { print; exit }')\"",
		)
	}
	return "set -eu; pve_updates=$(apt list --upgradable 2>/dev/null | sed '1d' | cut -d/ -f1 | while IFS= read -r package; do case \"$package\" in pve-*|proxmox-*|libpve-*) printf '%s,' \"$package\";; esac; done || true); printf 'BOETTICHER_PVE_UPDATES=%s\\n' \"$pve_updates\"; if test -e /var/run/reboot-required; then printf 'BOETTICHER_PVE_REBOOT=1\\n'; else printf 'BOETTICHER_PVE_REBOOT=0\\n'; fi; if ! (" + strings.Join(checks, " && ") + "); then exit 1; fi"
}

func hostUpdateStatus(output []byte) Component {
	found := false
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "BOETTICHER_PVE_REBOOT=1") {
			return Component{State: Attention, Detail: "Proxmox Host reboot required"}
		}
		if strings.HasPrefix(line, "BOETTICHER_PVE_UPDATES=") {
			found = true
			if strings.TrimPrefix(line, "BOETTICHER_PVE_UPDATES=") != "" {
				return Component{State: Attention, Detail: "Proxmox Host updates available"}
			}
		}
	}
	if !found {
		return Component{State: Attention, Detail: "Proxmox Host update state unavailable"}
	}
	return Component{State: Healthy, Detail: "No Proxmox Host updates or reboot required"}
}

type InternetTarget struct {
	Address    string
	ServerName string
}

var defaultInternetTargets = []InternetTarget{
	{Address: "1.1.1.1:443", ServerName: "cloudflare-dns.com"},
	{Address: "8.8.8.8:443", ServerName: "dns.google"},
}

func CheckInternet(ctx context.Context, targets []InternetTarget) CheckResult {
	if len(targets) == 0 {
		targets = defaultInternetTargets
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	for _, target := range targets {
		connection, err := dialer.DialContext(ctx, "tcp", target.Address)
		if err != nil {
			continue
		}
		tlsConnection := tls.Client(connection, &tls.Config{ServerName: target.ServerName, MinVersion: tls.VersionTLS12})
		handshakeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		err = tlsConnection.HandshakeContext(handshakeCtx)
		cancel()
		_ = tlsConnection.Close()
		if err == nil {
			return CheckResult{Configured: true, Healthy: true, Detail: "Internet connectivity is available"}
		}
	}
	return CheckResult{Configured: true, Detail: "Internet connectivity is unavailable"}
}

func RebootResult(path string) Component {
	if path == "" {
		path = DefaultRebootRequired
	}
	_, err := os.Stat(path)
	if err == nil {
		return Component{State: Attention, Detail: "Controller reboot required"}
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Component{State: Attention, Detail: "Controller reboot state cannot be inspected"}
	}
	return Component{State: Off}
}
