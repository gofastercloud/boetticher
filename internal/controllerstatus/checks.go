package controllerstatus

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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
	Detail     string
}

type CommandRunner func(context.Context, string, ...string) ([]byte, error)

func defaultCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

type ControllerChecker struct {
	ConfigPath       string
	RequiredServices []string
	RootPath         string
	RunCommand       CommandRunner
	Statfs           func(string, *syscall.Statfs_t) error
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
	return CheckResult{Configured: true, Healthy: true, Detail: "configuration, required services, and root filesystem are healthy"}
}

type HostChecker struct {
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
	if _, err := run(ctx, transport, command); err != nil {
		return CheckResult{Configured: true, Detail: "enrolled Host health check failed"}
	}
	return CheckResult{Configured: true, Healthy: true, Detail: "enrolled Host fundamentals are healthy"}
}

func hostHealthCommand(config controllerhost.LabConfig) string {
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
	checks := []string{
		"test \"$(hostname)\" = " + quote(config.Proxmox.Node),
		"for service in pve-cluster pvedaemon pvestatd pveproxy; do systemctl is-active --quiet \"$service\"; done",
		"ip -json address show | grep -Fq " + quote(config.Proxmox.Address),
	}
	if config.Storage != nil {
		checks = append(checks, "pvesm status --storage "+quote(config.Storage.GuestStorage)+" --output-format json | grep -Eq '\"active\"[[:space:]]*:[[:space:]]*1'")
	}
	if config.Network != nil {
		checks = append(checks,
			"ip -d link show vmbr1 | grep -Eq 'vlan_filtering (1|on)'",
			"test -z \"$(bridge link | awk '$NF == \\\"vmbr1\\\" { print; exit }')\"",
		)
	}
	return "set -eu; " + strings.Join(checks, " && ")
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

func DownloadThroughput(ctx context.Context, bytes int64) (float64, error) {
	if bytes <= 0 {
		bytes = DefaultTransferBytes
	}
	url := fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", bytes)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("User-Agent", "boetticher-status/1")
	client := &http.Client{Timeout: 15 * time.Second}
	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return 0, fmt.Errorf("throughput endpoint returned HTTP %d", response.StatusCode)
	}
	read, err := io.CopyN(io.Discard, response.Body, bytes)
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, err
	}
	if read <= 0 || time.Since(started) <= 0 {
		return 0, errors.New("throughput endpoint returned no usable sample")
	}
	return float64(read*8) / time.Since(started).Seconds() / 1_000_000, nil
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
