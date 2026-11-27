package agentlab

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestResolveConfigPath(t *testing.T) {
	home := "/tmp/fakehome"
	emptyEnv := func(string) string { return "" }

	got := ResolveConfigPath("", home, emptyEnv)
	want := filepath.Join(home, ".config", "groundhog", "agent-lab.yml")
	if got != want {
		t.Fatalf("default path = %q, want %q", got, want)
	}

	env := func(k string) string {
		if k == EnvConfigPath {
			return "~/custom/agent.yml"
		}
		return ""
	}
	got = ResolveConfigPath("", home, env)
	want = filepath.Join(home, "custom", "agent.yml")
	if got != want {
		t.Fatalf("env path = %q, want %q", got, want)
	}

	got = ResolveConfigPath("~/flag/agent.yml", home, env)
	want = filepath.Join(home, "flag", "agent.yml")
	if got != want {
		t.Fatalf("flag path = %q, want %q", got, want)
	}
}

func TestLoadConfigDefaultsAndStrictYAML(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "agent-lab.yml")

	if err := os.WriteFile(cfgPath, []byte("host: pi.lab.internal\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(cfgPath, tmp)
	if err != nil {
		t.Fatalf("LoadConfig unexpected error: %v", err)
	}
	if cfg.Host != "pi.lab.internal" {
		t.Fatalf("Host = %q, want pi.lab.internal", cfg.Host)
	}
	if cfg.User != DefaultUser {
		t.Fatalf("User = %q, want %q", cfg.User, DefaultUser)
	}
	if cfg.Port != DefaultPort {
		t.Fatalf("Port = %d, want %d", cfg.Port, DefaultPort)
	}
	wantID := filepath.Join(tmp, DefaultIdentityRel)
	if cfg.IdentityFile != wantID {
		t.Fatalf("IdentityFile = %q, want %q", cfg.IdentityFile, wantID)
	}
	wantKH := filepath.Join(tmp, DefaultKnownHostsRel)
	if cfg.KnownHostsFile != wantKH {
		t.Fatalf("KnownHostsFile = %q, want %q", cfg.KnownHostsFile, wantKH)
	}

	// Custom values with tilde expansion.
	customYAML := strings.Join([]string{
		"host: 192.168.10.2",
		"user: lab-agent",
		"port: 2222",
		"identity_file: ~/keys/id_ed25519",
		"known_hosts_file: ~/keys/known_hosts",
	}, "\n") + "\n"
	if err := os.WriteFile(cfgPath, []byte(customYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = LoadConfig(cfgPath, tmp)
	if err != nil {
		t.Fatalf("LoadConfig custom unexpected error: %v", err)
	}
	if cfg.User != "lab-agent" || cfg.Port != 2222 ||
		cfg.IdentityFile != filepath.Join(tmp, "keys", "id_ed25519") ||
		cfg.KnownHostsFile != filepath.Join(tmp, "keys", "known_hosts") {
		t.Fatalf("unexpected custom config: %+v", cfg)
	}

	// Strict YAML: unknown fields must fail.
	unknownYAML := "host: pi.lab.internal\nunknown_field: nope\n"
	if err := os.WriteFile(cfgPath, []byte(unknownYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(cfgPath, tmp); err == nil {
		t.Fatal("expected error for unknown YAML field, got nil")
	}

	// Missing required host must fail.
	if err := os.WriteFile(cfgPath, []byte("user: boetticher-agent\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(cfgPath, tmp); err == nil {
		t.Fatal("expected error for missing host, got nil")
	}

	// Invalid port (0 and >65535) must fail.
	for _, portYAML := range []string{"host: pi.lab.internal\nport: 0\n", "host: pi.lab.internal\nport: 70000\n"} {
		if err := os.WriteFile(cfgPath, []byte(portYAML), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(cfgPath, tmp); err == nil {
			t.Fatalf("expected error for invalid port config %q, got nil", portYAML)
		}
	}

	// Trailing YAML document must fail.
	if err := os.WriteFile(cfgPath, []byte("host: pi.lab.internal\n---\nhost: second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(cfgPath, tmp); err == nil {
		t.Fatal("expected error for trailing YAML document, got nil")
	}

	// Option-injection host or user starting with '-' must fail.
	if err := os.WriteFile(cfgPath, []byte("host: -oProxyCommand=evil\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(cfgPath, tmp); err == nil {
		t.Fatal("expected error for host starting with '-', got nil")
	}
	if err := os.WriteFile(cfgPath, []byte("host: pi.lab.internal\nuser: -evil\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(cfgPath, tmp); err == nil {
		t.Fatal("expected error for user starting with '-', got nil")
	}
}

func TestCheckSecurityFailClosed(t *testing.T) {
	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "agent_lab_ed25519")
	khPath := filepath.Join(tmp, "agent_lab_known_hosts")

	if err := os.WriteFile(keyPath, []byte("PRIVATE KEY"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Missing known_hosts_file must fail.
	cfg := Config{
		Host:           "pi.lab.internal",
		User:           DefaultUser,
		Port:           22,
		IdentityFile:   keyPath,
		KnownHostsFile: khPath,
	}
	if err := CheckSecurity(cfg); err == nil {
		t.Fatal("expected error when known_hosts_file is missing")
	}

	// Create known_hosts_file; valid 0600 key should pass.
	if err := os.WriteFile(khPath, []byte("pi.lab.internal ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckSecurity(cfg); err != nil {
		t.Fatalf("expected valid config to pass security check, got: %v", err)
	}

	// 0400 key should also pass.
	if err := os.Chmod(keyPath, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := CheckSecurity(cfg); err != nil {
		t.Fatalf("expected 0400 key to pass security check, got: %v", err)
	}

	// Any group/other permission bits (mode & 0077 != 0) must fail.
	for _, perm := range []os.FileMode{0o644, 0o640, 0o604, 0o660, 0o777} {
		if err := os.Chmod(keyPath, perm); err != nil {
			t.Fatal(err)
		}
		if err := CheckSecurity(cfg); err == nil {
			t.Fatalf("expected error for permissive key mode %#o", perm)
		}
	}

	// Restore 0600, test directory as known_hosts_file.
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	dirKH := filepath.Join(tmp, "kh_dir")
	if err := os.Mkdir(dirKH, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg.KnownHostsFile = dirKH
	if err := CheckSecurity(cfg); err == nil {
		t.Fatal("expected error when known_hosts_file is a directory")
	}

	// Missing identity_file must fail.
	cfg.KnownHostsFile = khPath
	cfg.IdentityFile = filepath.Join(tmp, "missing_key")
	if err := CheckSecurity(cfg); err == nil {
		t.Fatal("expected error when identity_file is missing")
	}
}

func TestBuildSSHArgsAndQuoting(t *testing.T) {
	cfg := Config{
		Host:           "pi.lab.internal",
		User:           "boetticher-agent",
		Port:           2222,
		IdentityFile:   "/tmp/keys/agent_lab_ed25519",
		KnownHostsFile: "/tmp/keys/agent_lab_known_hosts",
	}

	argv, err := BuildSSHArgs(cfg, []string{"controller", "status"})
	if err != nil {
		t.Fatalf("BuildSSHArgs unexpected error: %v", err)
	}

	want := []string{
		"-F", "/dev/null",
		"-i", "/tmp/keys/agent_lab_ed25519",
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "BatchMode=yes",
		"-o", "UserKnownHostsFile=/tmp/keys/agent_lab_known_hosts",
		"-p", "2222",
		"--",
		"boetticher-agent@pi.lab.internal",
		"boetticher controller status",
	}
	if !slices.Equal(argv, want) {
		t.Fatalf("BuildSSHArgs =\n%q\nwant:\n%q", argv, want)
	}

	// Safe quoting for spaces, single quotes, shell metacharacters, and empty args.
	quoted, err := FormatRemoteCommand([]string{"module", "logging", "query", "--match", "hello world", "it's", "; rm -rf /", ""})
	if err != nil {
		t.Fatalf("FormatRemoteCommand unexpected error: %v", err)
	}
	wantCmd := "boetticher module logging query --match 'hello world' 'it'\\''s' '; rm -rf /' ''"
	if quoted != wantCmd {
		t.Fatalf("FormatRemoteCommand = %q, want %q", quoted, wantCmd)
	}

	// NUL byte must be rejected.
	if _, err := FormatRemoteCommand([]string{"bad\x00arg"}); err == nil {
		t.Fatal("expected error for NUL byte in argument")
	}
}

func TestSanitizedEnvStripsSSHAuthSock(t *testing.T) {
	in := []string{"PATH=/usr/bin", "SSH_AUTH_SOCK=/tmp/secretive.sock", "HOME=/Users/test"}
	got := SanitizedEnv(in)
	for _, kv := range got {
		if strings.HasPrefix(kv, "SSH_AUTH_SOCK=") {
			t.Fatalf("SSH_AUTH_SOCK was not stripped: %v", got)
		}
	}
	if len(got) != 2 {
		t.Fatalf("unexpected env length %d: %v", len(got), got)
	}
}

func TestInitGeneratesKeyAndPrintsEnableCommand(t *testing.T) {
	tmp := t.TempDir()
	var stdout, stderr bytes.Buffer

	err := Run([]string{"init"}, Options{
		HomeDir: tmp,
		Getenv:  func(string) string { return "" },
		Stdout:  &stdout,
		Stderr:  &stderr,
	})
	if err != nil {
		t.Fatalf("init failed: %v (stderr: %s)", err, stderr.String())
	}

	keyPath := filepath.Join(tmp, DefaultIdentityRel)
	pubPath := keyPath + ".pub"

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("expected private key at %s: %v", keyPath, err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode = %#o, want 0600", info.Mode().Perm())
	}

	pubBytes, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("expected public key at %s: %v", pubPath, err)
	}
	pubKey := strings.TrimSpace(string(pubBytes))
	if !strings.HasPrefix(pubKey, "ssh-ed25519 ") {
		t.Fatalf("unexpected public key format: %q", pubKey)
	}

	out := stdout.String()
	wantEnable := "boetticher controller agent-access enable --key '" + pubKey + "' --yes"
	if !strings.Contains(out, pubKey) {
		t.Fatalf("stdout missing public key:\n%s", out)
	}
	if !strings.Contains(out, wantEnable) {
		t.Fatalf("stdout missing enable command %q:\n%s", wantEnable, out)
	}

	// Re-running init must not overwrite existing key.
	origKeyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	err = Run([]string{"init"}, Options{
		HomeDir: tmp,
		Getenv:  func(string) string { return "" },
		Stdout:  &stdout,
		Stderr:  &stderr,
	})
	if err != nil {
		t.Fatalf("second init failed: %v", err)
	}
	afterKeyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(origKeyBytes, afterKeyBytes) {
		t.Fatal("second init overwrote existing private key")
	}
	if !strings.Contains(stdout.String(), wantEnable) {
		t.Fatalf("second init stdout missing enable command:\n%s", stdout.String())
	}

	// Permissive existing key must be refused by init.
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Run([]string{"init"}, Options{
		HomeDir: tmp,
		Getenv:  func(string) string { return "" },
		Stdout:  &stdout,
		Stderr:  &stderr,
	}); err == nil {
		t.Fatal("expected init to refuse permissive existing key")
	}
}

func TestRunStatusAndForwarding(t *testing.T) {
	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "id_ed25519")
	khPath := filepath.Join(tmp, "known_hosts")
	cfgPath := filepath.Join(tmp, "agent-lab.yml")

	if err := os.WriteFile(keyPath, []byte("PRIVATE"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(khPath, []byte("pi.local ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgContent := "host: pi.local\nidentity_file: " + keyPath + "\nknown_hosts_file: " + khPath + "\n"
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o600); err != nil {
		t.Fatal(err)
	}

	var gotName string
	var gotArgs []string
	var gotEnv []string
	fakeRunner := func(name string, args []string, env []string, _ io.Reader, _, _ io.Writer) error {
		gotName = name
		gotArgs = slices.Clone(args)
		gotEnv = slices.Clone(env)
		return nil
	}

	// agent-lab status -> boetticher controller status
	err := Run([]string{"--config", cfgPath, "status"}, Options{
		HomeDir: tmp,
		Getenv:  func(string) string { return "" },
		RunSSH:  fakeRunner,
		Stdout:  io.Discard,
		Stderr:  io.Discard,
	})
	if err != nil {
		t.Fatalf("Run status failed: %v", err)
	}
	if gotName != "ssh" {
		t.Fatalf("runner name = %q, want ssh", gotName)
	}
	if gotArgs[len(gotArgs)-1] != "boetticher controller status" {
		t.Fatalf("remote command = %q, want 'boetticher controller status'", gotArgs[len(gotArgs)-1])
	}
	for _, kv := range gotEnv {
		if strings.HasPrefix(kv, "SSH_AUTH_SOCK=") {
			t.Fatalf("SSH_AUTH_SOCK leaked into ssh env")
		}
	}

	// agent-lab -- host status --details -> boetticher host status --details
	err = Run([]string{"--config=" + cfgPath, "--", "host", "status", "--details"}, Options{
		HomeDir: tmp,
		Getenv:  func(string) string { return "" },
		RunSSH:  fakeRunner,
		Stdout:  io.Discard,
		Stderr:  io.Discard,
	})
	if err != nil {
		t.Fatalf("Run forwarded args failed: %v", err)
	}
	if gotArgs[len(gotArgs)-1] != "boetticher host status --details" {
		t.Fatalf("remote command = %q, want 'boetticher host status --details'", gotArgs[len(gotArgs)-1])
	}

	// Propagates exit error.
	errRunner := func(string, []string, []string, io.Reader, io.Writer, io.Writer) error {
		return ExitError{Code: 42}
	}
	err = Run([]string{"--config", cfgPath, "host", "status"}, Options{
		HomeDir: tmp,
		Getenv:  func(string) string { return "" },
		RunSSH:  errRunner,
		Stdout:  io.Discard,
		Stderr:  io.Discard,
	})
	var exitErr ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != 42 {
		t.Fatalf("expected ExitError{Code: 42}, got %v", err)
	}

	// Fail-closed: permissive key prevents ssh from ever being invoked.
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	called := false
	err = Run([]string{"--config", cfgPath, "status"}, Options{
		HomeDir: tmp,
		Getenv:  func(string) string { return "" },
		RunSSH: func(string, []string, []string, io.Reader, io.Writer, io.Writer) error {
			called = true
			return nil
		},
		Stdout: io.Discard,
		Stderr: io.Discard,
	})
	if err == nil {
		t.Fatal("expected error for permissive key in Run")
	}
	if called {
		t.Fatal("ssh runner must not be called when security check fails")
	}
}
