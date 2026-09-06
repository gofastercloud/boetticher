package controller

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	InstallRoot       = "/opt/boetticher"
	CurrentRelease    = InstallRoot + "/current"
	VenvPath          = InstallRoot + "/venv"
	ControllerConfig  = "/etc/boetticher/controller.yml"
	ControllerState   = "/var/lib/boetticher/controller"
	ControllerLog     = "/var/log/boetticher/bootstrap.log"
	Log2RAMBootMarker = ControllerState + "/log2ram-installed-boot-id"
)

type Config struct {
	OperatorUser string `yaml:"operator_user"`
	Blinkt       struct {
		Enabled  bool `yaml:"enabled"`
		GPIOChip int  `yaml:"gpiochip"`
	} `yaml:"blinkt"`
}

type Check struct {
	Name   string
	Passed bool
	Detail string
}

type StatusOptions struct {
	RuntimeDir string
	ConfigPath string
	StateDir   string
	MarkerPath string
	Operator   string
	Command    func(context.Context, string, ...string) ([]byte, error)
}

type StatusSnapshot struct {
	Platform       bool
	Runtime        bool
	Go             bool
	Ansible        bool
	SSH            bool
	Updates        bool
	Timers         bool
	Time           bool
	Journal        bool
	Logrotate      bool
	Log2RAM        bool
	Log2RAMTimer   bool
	RebootComplete bool
	GPIO           bool
}

func EvaluateSnapshot(snapshot StatusSnapshot) []Check {
	return []Check{
		{Name: "Platform", Passed: snapshot.Platform, Detail: "Raspberry Pi OS Trixie, ARM64"},
		{Name: "Controller runtime", Passed: snapshot.Runtime, Detail: "Installed"},
		{Name: "Go", Passed: snapshot.Go, Detail: "1.26.5"},
		{Name: "Ansible", Passed: snapshot.Ansible, Detail: "2.19.11"},
		{Name: "SSH", Passed: snapshot.SSH, Detail: "Public-key authentication; root login disabled"},
		{Name: "Security updates", Passed: snapshot.Updates, Detail: "Enabled; automatic reboot disabled"},
		{Name: "APT timers", Passed: snapshot.Timers, Detail: "Enabled"},
		{Name: "Time", Passed: snapshot.Time, Detail: "Synchronized"},
		{Name: "Journal limits", Passed: snapshot.Journal, Detail: "Configured"},
		{Name: "Log rotation", Passed: snapshot.Logrotate, Detail: "Configured"},
		{Name: "RAM logging", Passed: snapshot.Log2RAM, Detail: "log2ram service and /var/log mount"},
		{Name: "RAM logging timer", Passed: snapshot.Log2RAMTimer, Detail: "Synchronization timer"},
		{Name: "Reboot", Passed: snapshot.RebootComplete, Detail: "Required activation reboot completed"},
		{Name: "GPIO", Passed: snapshot.GPIO, Detail: "Configured Blinkt hardware path"},
	}
}

func RunStatus(ctx context.Context, options StatusOptions) ([]Check, error) {
	if options.RuntimeDir == "" {
		options.RuntimeDir = CurrentRelease
	}
	if options.ConfigPath == "" {
		options.ConfigPath = ControllerConfig
	}
	if options.StateDir == "" {
		options.StateDir = ControllerState
	}
	if options.MarkerPath == "" {
		options.MarkerPath = Log2RAMBootMarker
	}
	if options.Operator == "" {
		options.Operator = "pi"
	}
	if options.Command == nil {
		options.Command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).Output()
		}
	}
	config, configErr := LoadConfig(options.ConfigPath)
	checks := make([]Check, 0, 14)
	checks = append(checks, Check{Name: "Platform", Passed: platformReady(ctx, options.Command), Detail: "Raspberry Pi OS Trixie, ARM64"})
	checks = append(checks, Check{Name: "Controller runtime", Passed: runtimeReady(options.RuntimeDir), Detail: "Installed"})
	checks = append(checks, Check{Name: "Go", Passed: commandContains(ctx, options.Command, "/usr/local/bin/go", "version", "go1.26.5"), Detail: "1.26.5"})
	checks = append(checks, Check{Name: "Ansible", Passed: commandContains(ctx, options.Command, filepath.Join(VenvPath, "bin", "ansible-playbook"), "--version", "core 2.19.11"), Detail: "2.19.11"})
	checks = append(checks, Check{Name: "SSH", Passed: sshReady(ctx, options.Command, options.Operator), Detail: "Public-key authentication; root login disabled"})
	checks = append(checks, Check{Name: "Security updates", Passed: fileContains("/etc/apt/apt.conf.d/52boetticher-unattended", "Unattended-Upgrade::Automatic-Reboot \"false\";", "origin=Debian,codename=trixie-security"), Detail: "Enabled; automatic reboot disabled"})
	checks = append(checks, Check{Name: "APT timers", Passed: unitReady(ctx, options.Command, "apt-daily.timer") && unitReady(ctx, options.Command, "apt-daily-upgrade.timer"), Detail: "Enabled"})
	checks = append(checks, Check{Name: "Time", Passed: commandEquals(ctx, options.Command, "timedatectl", "show", "-p", "NTPSynchronized", "--value", "yes"), Detail: "Synchronized"})
	checks = append(checks, Check{Name: "Journal limits", Passed: fileContains("/etc/systemd/journald.conf.d/60-boetticher-controller.conf", "Storage=persistent", "SystemMaxUse=32M", "RuntimeMaxUse=16M"), Detail: "Configured"})
	checks = append(checks, Check{Name: "Log rotation", Passed: fileContains("/etc/logrotate.d/boetticher-controller", "/var/log/boetticher/*.log", "rotate 7"), Detail: "Configured"})
	checks = append(checks, Check{Name: "RAM logging", Passed: commandSucceeds(ctx, options.Command, "systemctl", "is-active", "--quiet", "log2ram.service") && commandEquals(ctx, options.Command, "findmnt", "-rn", "--mountpoint", "/var/log", "-o", "FSTYPE", "tmpfs"), Detail: "log2ram service and /var/log mount"})
	checks = append(checks, Check{Name: "RAM logging timer", Passed: commandContains(ctx, options.Command, "systemctl", "list-timers", "--all", "log2ram*", "log2ram"), Detail: "Synchronization timer"})
	checks = append(checks, Check{Name: "Reboot", Passed: rebootComplete(options.MarkerPath), Detail: "Required activation reboot completed"})
	gpioReady := configErr == nil && config.Blinkt.Enabled && config.Blinkt.GPIOChip >= 0 && commandSucceeds(ctx, options.Command, "/usr/bin/python3", "-c", "import lgpio")
	checks = append(checks, Check{Name: "GPIO", Passed: gpioReady, Detail: "Configured Blinkt hardware path"})
	return checks, nil
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var config Config
	// Chip zero is valid, so an omitted chip must remain distinguishable and
	// trigger discovery during bootstrap.
	config.Blinkt.GPIOChip = -1
	if err := yaml.Unmarshal(data, &config); err != nil {
		return Config{}, fmt.Errorf("decode controller config: %w", err)
	}
	if config.OperatorUser == "" {
		return Config{}, fmt.Errorf("controller config has no operator_user")
	}
	return config, nil
}

func platformReady(ctx context.Context, command func(context.Context, string, ...string) ([]byte, error)) bool {
	osRelease, err := os.ReadFile("/etc/os-release")
	model, modelErr := os.ReadFile("/proc/device-tree/model")
	if err != nil || modelErr != nil || !strings.Contains(string(osRelease), "VERSION_CODENAME=trixie") || !strings.Contains(string(osRelease), "ID=debian") || !strings.Contains(string(model), "Raspberry Pi") {
		return false
	}
	arch, err := command(ctx, "dpkg", "--print-architecture")
	if err != nil || strings.TrimSpace(string(arch)) != "arm64" {
		return false
	}
	uname, err := command(ctx, "uname", "-m")
	return err == nil && strings.TrimSpace(string(uname)) == "aarch64"
}

func runtimeReady(runtime string) bool {
	resolved, err := filepath.EvalSymlinks(runtime)
	if err != nil || resolved == "" {
		return false
	}
	for _, path := range []string{filepath.Join(resolved, "bin", "boetticher"), filepath.Join(resolved, "controller", "bootstrap.yml"), filepath.Join(resolved, "controller", "requirements.txt"), filepath.Join(resolved, "controller", "libexec", "boetticher-bootstrap-led")} {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return false
		}
		if filepath.Base(path) == "boetticher" || filepath.Base(path) == "boetticher-bootstrap-led" {
			if info.Mode()&0111 == 0 {
				return false
			}
		}
	}
	return true
}

func commandContains(ctx context.Context, command func(context.Context, string, ...string) ([]byte, error), name string, args ...string) bool {
	needle := ""
	if len(args) > 0 {
		needle = args[len(args)-1]
		args = args[:len(args)-1]
	}
	out, err := command(ctx, name, args...)
	return err == nil && (needle == "" || strings.Contains(string(out), needle))
}

func commandEquals(ctx context.Context, command func(context.Context, string, ...string) ([]byte, error), name string, args ...string) bool {
	want := ""
	if len(args) > 0 {
		want = args[len(args)-1]
		args = args[:len(args)-1]
	}
	out, err := command(ctx, name, args...)
	return err == nil && strings.TrimSpace(string(out)) == want
}

func commandSucceeds(ctx context.Context, command func(context.Context, string, ...string) ([]byte, error), name string, args ...string) bool {
	_, err := command(ctx, name, args...)
	return err == nil
}

func unitReady(ctx context.Context, command func(context.Context, string, ...string) ([]byte, error), unit string) bool {
	return commandEquals(ctx, command, "systemctl", "is-enabled", "--quiet", unit, "") && commandEquals(ctx, command, "systemctl", "is-active", "--quiet", unit, "")
}

func sshReady(ctx context.Context, command func(context.Context, string, ...string) ([]byte, error), operator string) bool {
	out, err := command(ctx, "/usr/sbin/sshd", "-T", "-C", "user="+operator+",addr=127.0.0.1,host=localhost")
	if err != nil {
		return false
	}
	text := string(out)
	for _, setting := range []string{"pubkeyauthentication yes", "passwordauthentication no", "kbdinteractiveauthentication no", "permitrootlogin no", "x11forwarding no"} {
		if !strings.Contains(text, setting) {
			return false
		}
	}
	return true
}

func fileContains(path string, needles ...string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	text := string(data)
	for _, needle := range needles {
		if !strings.Contains(text, needle) {
			return false
		}
	}
	return true
}

func rebootComplete(marker string) bool {
	markerData, err := os.ReadFile(marker)
	if err != nil {
		return false
	}
	bootData, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return err == nil && strings.TrimSpace(string(markerData)) != "" && strings.TrimSpace(string(markerData)) != strings.TrimSpace(string(bootData))
}
