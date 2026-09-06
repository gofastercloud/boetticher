package controller

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGPIOServiceActiveStopsBootstrapWhenOwnerIsActive(t *testing.T) {
	active, err := gpioServiceActive(context.Background(), func(context.Context, string, ...string) ([]byte, error) {
		return nil, nil
	})
	if err != nil || !active {
		t.Fatalf("gpioServiceActive() = %v, %v; want active", active, err)
	}
	if _, err := gpioServiceActive(context.Background(), func(context.Context, string, ...string) ([]byte, error) {
		return nil, exec.ErrNotFound
	}); err != nil {
		t.Fatalf("missing systemctl should be treated as inactive: %v", err)
	}
}

func TestParseGPIOChipOutputRequiresOneChipWithHeaderLines(t *testing.T) {
	output := `gpiochip0 - 28 lines:
	line   0: "GPIO0" input active-high [used]
	line  23: "GPIO23" input active-high
	line  24: "GPIO24" input active-high
gpiochip1 - 28 lines:
	line  23: "GPIO23" input active-high
`
	if got, err := ParseGPIOChipOutput(output); err != nil || got != 0 {
		t.Fatalf("ParseGPIOChipOutput() = %d, %v; want chip 0", got, err)
	}
	if _, err := ParseGPIOChipOutput(output + "line 24: GPIO24\n"); err == nil {
		t.Fatal("ambiguous GPIO chip output was accepted")
	}
}

func TestParseGPIOChipOutputRejectsMissingHeaderPins(t *testing.T) {
	if _, err := ParseGPIOChipOutput("gpiochip0 - 28 lines:\nline 23: GPIO23\n"); err == nil {
		t.Fatal("GPIO output without both header pins was accepted")
	}
}

func TestCleanEnvironmentDropsInheritedAutomationOverrides(t *testing.T) {
	previous := os.Environ()
	os.Clearenv()
	os.Setenv("ANSIBLE_CONFIG", "/untrusted/config")
	os.Setenv("PYTHONPATH", "/untrusted/python")
	os.Setenv("PATH", "/usr/bin")
	env := cleanEnvironment("/opt/boetticher/releases/test")
	os.Clearenv()
	for _, value := range previous {
		parts := strings.SplitN(value, "=", 2)
		if len(parts) == 2 {
			os.Setenv(parts[0], parts[1])
		}
	}
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "ANSIBLE_CONFIG=/untrusted/config") || strings.Contains(joined, "PYTHONPATH=") {
		t.Fatalf("untrusted environment survived: %s", joined)
	}
	for _, required := range []string{"ANSIBLE_CONFIG=/opt/boetticher/releases/test/controller/ansible.cfg", "ANSIBLE_NOCOLOR=1", "PYTHONNOUSERSITE=1", "LC_ALL=C.UTF-8"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("clean environment missing %q", required)
		}
	}
}

func TestRunBootstrapRejectsMissingKeyConfirmationBeforeMutation(t *testing.T) {
	called := false
	err := RunBootstrap(context.Background(), BootstrapOptions{ConfirmKeyLogin: false, isRoot: func() bool { return true }, Run: func(context.Context, string, []string, string, []string, io.Writer, io.Writer) error {
		called = true
		return nil
	}}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "confirm-key-login") {
		t.Fatalf("missing key confirmation error = %v", err)
	}
	if called {
		t.Fatal("Ansible was invoked without key-login confirmation")
	}
}

func TestRunBootstrapReportsSubprocessFailure(t *testing.T) {
	root := t.TempDir()
	releases := filepath.Join(root, "releases", "build")
	if err := os.MkdirAll(filepath.Join(releases, "bin"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(releases, "controller", "libexec"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(releases, "BUILD_ID"), []byte("build\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(releases, "bin", "boetticher"), []byte("binary"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(releases, "controller", "bootstrap.yml"), []byte("---\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(releases, "controller", "requirements.txt"), []byte("ansible-core==2.19.11\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(releases, "controller", "ansible.cfg"), []byte("[defaults]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(releases, "controller", "libexec", "boetticher-bootstrap-led"), []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	runtime := filepath.Join(root, "current")
	if err := os.Symlink(releases, runtime); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "controller.yml")
	config := "operator_user: pi\nblinkt:\n  enabled: false\n  gpiochip: -1\n"
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(root, "bootstrap.lock")
	logPath := filepath.Join(root, "bootstrap.log")
	var output strings.Builder
	wantErr := errors.New("child failed")
	err := RunBootstrap(context.Background(), BootstrapOptions{
		Operator:        "pi",
		ConfirmKeyLogin: true,
		RuntimeDir:      runtime,
		ConfigPath:      configPath,
		LockPath:        lockPath,
		LogPath:         logPath,
		Run:             func(context.Context, string, []string, string, []string, io.Writer, io.Writer) error { return wantErr },
		ShowLED:         func(context.Context, string, int, string) error { return nil },
		runtimeRoot:     root,
		isRoot:          func() bool { return true },
	}, &output, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "Ansible bootstrap failed") {
		t.Fatalf("bootstrap failure = %v", err)
	}
	if !strings.Contains(output.String(), "RUNNING") {
		t.Fatalf("bootstrap output omitted running state: %s", output.String())
	}
}
