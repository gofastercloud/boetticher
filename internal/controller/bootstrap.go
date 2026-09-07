package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/gofastercloud/boetticher/internal/controllerstatus"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

var gpioChipHeader = regexp.MustCompile(`^gpiochip([0-9]+)\s+-\s+([0-9]+) lines?:`)
var gpioLine = regexp.MustCompile(`^\s*line\s+(23|24):`)

type BootstrapOptions struct {
	Operator        string
	ConfirmKeyLogin bool
	RuntimeDir      string
	ConfigPath      string
	MarkerPath      string
	LockPath        string
	LogPath         string
	Command         func(context.Context, string, ...string) ([]byte, error)
	Run             func(context.Context, string, []string, string, []string, io.Writer, io.Writer) error
	PlatformReady   func(context.Context, func(context.Context, string, ...string) ([]byte, error)) bool
	runtimeRoot     string
	isRoot          func() bool
}

type RebootRequiredError struct{}

func (RebootRequiredError) Error() string { return "reboot required to activate log2ram" }

func RunBootstrap(ctx context.Context, options BootstrapOptions, out, errOut io.Writer) error {
	isRoot := options.isRoot
	if isRoot == nil {
		isRoot = func() bool { return os.Geteuid() == 0 }
	}
	if !isRoot() {
		return errors.New("controller bootstrap requires root; run it with sudo")
	}
	if options.Operator == "" {
		options.Operator = "pi"
	}
	if !options.ConfirmKeyLogin {
		return errors.New("--confirm-key-login is required before SSH password authentication is disabled")
	}
	if options.RuntimeDir == "" {
		options.RuntimeDir = CurrentRelease
	}
	if options.ConfigPath == "" {
		options.ConfigPath = ControllerConfig
	}
	if options.MarkerPath == "" {
		options.MarkerPath = Log2RAMBootMarker
	}
	if options.LockPath == "" {
		options.LockPath = "/run/lock/boetticher-controller-bootstrap.lock"
	}
	if options.LogPath == "" {
		options.LogPath = ControllerLog
	}
	if options.Command == nil {
		options.Command = defaultCommand
	}
	if options.Run == nil {
		options.Run = defaultRun
	}
	if options.PlatformReady == nil {
		options.PlatformReady = platformReady
	}
	if !options.PlatformReady(ctx, options.Command) {
		return errors.New("controller bootstrap requires Debian 13/Trixie on Raspberry Pi ARM64")
	}
	if err := os.MkdirAll(filepath.Dir(options.LockPath), 0755); err != nil {
		return fmt.Errorf("create bootstrap lock directory: %w", err)
	}
	lock, err := os.OpenFile(options.LockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open bootstrap lock: %w", err)
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return errors.New("controller bootstrap is already running")
		}
		return fmt.Errorf("lock bootstrap: %w", err)
	}
	if active, err := gpioServiceActive(ctx, options.Command); err != nil {
		return err
	} else if active {
		return errors.New("blinkt-pattern.service is active; stop the existing GPIO controller before bootstrapping")
	}

	config, configErr := LoadConfig(options.ConfigPath)
	if configErr == nil && config.OperatorUser != options.Operator {
		return fmt.Errorf("controller operator %q does not match configured operator %q", options.Operator, config.OperatorUser)
	}
	if configErr != nil && !errors.Is(configErr, os.ErrNotExist) {
		return configErr
	}
	if configErr != nil {
		config.OperatorUser = options.Operator
		config.Blinkt.Enabled = true
		if chip, discoverErr := discoverGPIOChip(ctx, options.Command); discoverErr == nil {
			config.Blinkt.GPIOChip = chip
		} else {
			config.Blinkt.Enabled = false
			config.Blinkt.GPIOChip = -1
			fmt.Fprintf(errOut, "Blinkt: NOT PRESENT — %s; continuing without optional display\n", discoverErr)
		}
		if saveErr := saveConfig(options.ConfigPath, config); saveErr != nil {
			return saveErr
		}
	} else if config.Blinkt.Enabled && config.Blinkt.GPIOChip < 0 {
		if chip, discoverErr := discoverGPIOChip(ctx, options.Command); discoverErr == nil {
			config.Blinkt.GPIOChip = chip
			if saveErr := saveConfig(options.ConfigPath, config); saveErr != nil {
				return saveErr
			}
		} else {
			fmt.Fprintf(errOut, "Blinkt: FAIL — %s\n", discoverErr)
		}
	}
	if rebootRequired(options.MarkerPath) {
		fmt.Fprintln(out, "Bootstrap configuration: FAIL")
		fmt.Fprintln(out, "Controller readiness: FAIL — reboot required to activate log2ram")
		fmt.Fprintln(out, "\nNext:\n  sudo reboot\n\nAfter reconnecting:\n  sudo boetticher controller bootstrap --operator "+options.Operator+" --confirm-key-login")
		return RebootRequiredError{}
	}

	controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-start", Name: "controller bootstrap", Steps: 4})
	fmt.Fprintln(out, "Bootstrap configuration: RUNNING")
	runtimeRoot := options.runtimeRoot
	if runtimeRoot == "" {
		runtimeRoot = InstallRoot
	}
	runtimeDir, err := resolveRuntimeUnder(options.RuntimeDir, runtimeRoot)
	if err != nil {
		controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-failure", Name: "controller bootstrap", Detail: err.Error()})
		return err
	}
	if err := os.MkdirAll(filepath.Dir(options.LogPath), 0700); err != nil {
		return fmt.Errorf("create bootstrap log directory: %w", err)
	}
	logFile, err := os.OpenFile(options.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("open bootstrap log: %w", err)
	}
	defer logFile.Close()
	stream := io.MultiWriter(out, logFile)
	extra, err := json.Marshal(map[string]string{"controller_operator_user": options.Operator})
	if err != nil {
		return fmt.Errorf("encode controller Ansible variables: %w", err)
	}
	env := cleanEnvironment(runtimeDir)
	playbook := filepath.Join(runtimeDir, "controller", "bootstrap.yml")
	ansible := filepath.Join(VenvPath, "bin", "ansible-playbook")
	args := []string{"-i", "localhost,", "-c", "local", playbook, "--extra-vars", string(extra)}
	if err := options.Run(ctx, ansible, args, runtimeDir, env, stream, stream); err != nil {
		controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-failure", Name: "controller bootstrap", Detail: err.Error()})
		if errors.Is(ctx.Err(), context.Canceled) {
			return fmt.Errorf("controller bootstrap interrupted: %w", ctx.Err())
		}
		return fmt.Errorf("controller Ansible bootstrap failed: %w", err)
	}
	controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-progress", Name: "controller bootstrap", CurrentStep: 2, TotalSteps: 4, Detail: "Controller configuration applied"})
	checks, _ := RunStatus(ctx, StatusOptions{RuntimeDir: runtimeDir, ConfigPath: options.ConfigPath, MarkerPath: options.MarkerPath, Operator: options.Operator, Command: options.Command})
	failed := false
	reboot := false
	for _, check := range checks {
		state := "FAIL"
		if check.Passed {
			state = "PASS"
		} else if check.Optional {
			state = "NOT TESTED"
		} else {
			failed = true
			reboot = reboot || check.Name == "Reboot"
		}
		fmt.Fprintf(out, "%s  %-20s %s\n", state, check.Name, check.Detail)
	}
	if failed {
		if reboot {
			fmt.Fprintln(out, "\nController readiness: FAIL — reboot required to activate log2ram")
			fmt.Fprintln(out, "Next:\n  sudo reboot")
		} else {
			fmt.Fprintln(out, "\nController readiness: FAIL")
		}
		controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-failure", Name: "controller bootstrap", Detail: "Controller readiness failed"})
		return errors.New("controller readiness failed")
	}
	controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-progress", Name: "controller bootstrap", CurrentStep: 3, TotalSteps: 4, Detail: "Controller readiness verified"})
	fmt.Fprintln(out, "\nBootstrap configuration: PASS\nController readiness: PASS")
	controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-success", Name: "controller bootstrap"})
	return nil
}

func resolveRuntimeUnder(runtime, root string) (string, error) {
	resolved, err := filepath.EvalSymlinks(runtime)
	if err != nil {
		return "", fmt.Errorf("resolve controller runtime: %w", err)
	}
	releasesRoot, err := filepath.EvalSymlinks(filepath.Join(root, "releases"))
	if err != nil {
		return "", fmt.Errorf("resolve controller releases: %w", err)
	}
	rel, err := filepath.Rel(releasesRoot, resolved)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("controller runtime is outside %s/releases", root)
	}
	return resolved, nil
}

func cleanEnvironment(runtime string) []string {
	env := make([]string, 0, len(os.Environ())+4)
	for _, value := range os.Environ() {
		if strings.HasPrefix(value, "ANSIBLE_") || strings.HasPrefix(value, "PYTHONPATH=") {
			continue
		}
		env = append(env, value)
	}
	env = append(env,
		"ANSIBLE_CONFIG="+filepath.Join(runtime, "controller", "ansible.cfg"),
		"ANSIBLE_NOCOLOR=1",
		"PYTHONNOUSERSITE=1",
		"LC_ALL=C.UTF-8",
	)
	return env
}

func defaultCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOWORK=off", "GOPROXY=off")
	return command.Output()
}

func defaultRun(ctx context.Context, name string, args []string, dir string, env []string, stdout, stderr io.Writer) error {
	command := exec.CommandContext(ctx, name, args...)
	command.Dir = dir
	command.Env = env
	command.Stdout = stdout
	command.Stderr = stderr
	return command.Run()
}

func discoverGPIOChip(ctx context.Context, command func(context.Context, string, ...string) ([]byte, error)) (int, error) {
	output, err := command(ctx, "/usr/bin/gpioinfo")
	if err != nil {
		return -1, fmt.Errorf("discover GPIO chip: %w", err)
	}
	return ParseGPIOChipOutput(string(output))
}

func gpioServiceActive(ctx context.Context, command func(context.Context, string, ...string) ([]byte, error)) (bool, error) {
	_, err := command(ctx, "systemctl", "is-active", "--quiet", "blinkt-pattern.service")
	if err == nil {
		return true, nil
	}
	// Inactive or absent is safe. Other failures are not evidence that GPIO
	// ownership is absent, so stop rather than risk competing pin control.
	if exitErr, ok := err.(*exec.ExitError); ok && (exitErr.ExitCode() == 3 || exitErr.ExitCode() == 4) {
		return false, nil
	}
	if errors.Is(err, exec.ErrNotFound) {
		return false, nil
	}
	return false, fmt.Errorf("check existing GPIO controller: %w", err)
}

func ParseGPIOChipOutput(output string) (int, error) {
	chip := -1
	seenLines := map[int]map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		if match := gpioChipHeader.FindStringSubmatch(line); match != nil {
			var err error
			chip, err = strconv.Atoi(match[1])
			if err != nil {
				return -1, err
			}
			if seenLines[chip] == nil {
				seenLines[chip] = map[string]bool{}
			}
			continue
		}
		if chip >= 0 {
			if match := gpioLine.FindStringSubmatch(line); match != nil {
				seenLines[chip][match[1]] = true
			}
		}
	}
	found := -1
	for candidate, lines := range seenLines {
		if lines["23"] && lines["24"] {
			if found >= 0 {
				return -1, errors.New("GPIO23/GPIO24 are ambiguous across GPIO chips")
			}
			found = candidate
		}
	}
	if found < 0 {
		return -1, errors.New("no GPIO chip unambiguously exposes header GPIO23 and GPIO24")
	}
	return found, nil
}

func saveConfig(path string, config Config) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("encode controller config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create controller config directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".controller.yml-")
	if err != nil {
		return fmt.Errorf("stage controller config: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("activate controller config: %w", err)
	}
	return nil
}

func rebootRequired(marker string) bool {
	markerData, markerErr := os.ReadFile(marker)
	bootData, bootErr := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return markerErr == nil && bootErr == nil && strings.TrimSpace(string(markerData)) != "" && strings.TrimSpace(string(markerData)) == strings.TrimSpace(string(bootData))
}
