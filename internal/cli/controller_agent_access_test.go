package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/controller"
	"golang.org/x/crypto/ssh"
)

func testAgentSSHKey(t *testing.T, comment string) (string, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	if comment != "" {
		line += " " + comment
	}
	return line, ssh.FingerprintSHA256(sshPub)
}

func TestControllerAgentAccessHelpIsPublished(t *testing.T) {
	for _, args := range [][]string{
		{"controller", "agent-access", "--help"},
		{"controller", "agent-access", "status", "--help"},
		{"controller", "agent-access", "enable", "--help"},
		{"controller", "agent-access", "disable", "--help"},
	} {
		var out bytes.Buffer
		if err := Run(args, &out, &out); err != nil {
			t.Fatalf("%v failed: %v", args, err)
		}
		text := out.String()
		if !strings.Contains(text, "boetticher controller agent-access") {
			t.Fatalf("%v omitted command usage: %s", args, text)
		}
	}
}

func TestControllerAgentAccessDispatchAndFlags(t *testing.T) {
	var out bytes.Buffer
	if err := runController([]string{"agent-access"}, &out, &out); err == nil {
		t.Fatal("expected usage error for bare controller agent-access")
	}
	if err := runController([]string{"agent-access", "unknown"}, &out, &out); err == nil {
		t.Fatal("expected error for unknown agent-access subcommand")
	}
	if err := runController([]string{"agent-access", "enable", "--plan", "--yes", "--key", "ssh-ed25519 AAAA"}, &out, &out); err == nil {
		t.Fatal("expected error when both --plan and --yes are passed")
	}
	if err := runController([]string{"agent-access", "enable", "--plan"}, &out, &out); err == nil {
		t.Fatal("expected error when --key is missing")
	}
	if err := runController([]string{"agent-access", "disable", "--plan", "--yes"}, &out, &out); err == nil {
		t.Fatal("expected error when both --plan and --yes are passed to disable")
	}
}

func TestControllerAgentAccessCLILifecycle(t *testing.T) {
	tmp := t.TempDir()
	homeDir := filepath.Join(tmp, "home", "boetticher-agent")
	brokerPath := filepath.Join(tmp, "libexec", "boetticher-agent-broker")
	sudoersPath := filepath.Join(tmp, "sudoers.d", "boetticher-agent-broker")
	policyPath := filepath.Join(tmp, "etc", "agent-policy.yml")
	if err := os.MkdirAll(filepath.Dir(brokerPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(brokerPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	userCreated := false
	keyLine, fp := testAgentSSHKey(t, "agent-cli@mac")

	opts := controller.AgentAccessOptions{
		BrokerPath:       brokerPath,
		SudoersPath:      sudoersPath,
		PolicyPath:       policyPath,
		PolicyOwnerCheck: func(os.FileInfo) error { return nil },
		IsRoot:           func() bool { return true },
		Chown:            func(string, int, int) error { return nil },
		LookPath: func(string) (string, error) {
			return "", exec.ErrNotFound
		},
		LookupUser: func(name string) (controller.AgentUserInfo, bool, error) {
			if !userCreated {
				return controller.AgentUserInfo{}, false, nil
			}
			return controller.AgentUserInfo{Username: name, UID: 999, GID: 999, HomeDir: homeDir}, true, nil
		},
		Command: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name == "useradd" {
				userCreated = true
				if err := os.MkdirAll(homeDir, 0o755); err != nil {
					return nil, err
				}
			}
			return nil, nil
		},
	}

	// Plan is read-only and previews changes.
	var out bytes.Buffer
	if err := runControllerAgentAccessWithOptions([]string{"enable", "--key", keyLine, "--plan"}, opts, &out); err != nil {
		t.Fatalf("enable --plan failed: %v", err)
	}
	if !strings.Contains(out.String(), fp) || userCreated {
		t.Fatalf("unexpected plan output or mutation (userCreated=%v): %s", userCreated, out.String())
	}

	// Enable without --plan or --yes refuses to mutate.
	out.Reset()
	if err := runControllerAgentAccessWithOptions([]string{"enable", "--key", keyLine}, opts, &out); err == nil {
		t.Fatal("expected enable without --yes to refuse mutation")
	}
	if userCreated {
		t.Fatal("enable without --yes mutated state")
	}

	// Enable --yes applies.
	out.Reset()
	if err := runControllerAgentAccessWithOptions([]string{"enable", "--key", keyLine, "--yes"}, opts, &out); err != nil {
		t.Fatalf("enable --yes failed: %v", err)
	}

	// Status reports fingerprint and comment, never raw key bytes.
	out.Reset()
	if err := runControllerAgentAccessWithOptions([]string{"status"}, opts, &out); err != nil {
		t.Fatalf("status failed: %v", err)
	}
	statusText := out.String()
	for _, want := range []string{"boetticher-agent", "installed", fp, "agent-cli@mac", "read-only"} {
		if !strings.Contains(statusText, want) {
			t.Errorf("status output missing %q:\n%s", want, statusText)
		}
	}
	rawKeyData := strings.Fields(keyLine)[1]
	if strings.Contains(statusText, rawKeyData) {
		t.Fatalf("status output leaked raw key data:\n%s", statusText)
	}

	// Disable --plan is read-only.
	out.Reset()
	if err := runControllerAgentAccessWithOptions([]string{"disable", "--plan"}, opts, &out); err != nil {
		t.Fatalf("disable --plan failed: %v", err)
	}
	if _, err := os.Stat(sudoersPath); err != nil {
		t.Fatalf("disable --plan removed sudoers: %v", err)
	}

	// Disable --yes removes authorized_keys and sudoers, preserves policy.
	out.Reset()
	if err := runControllerAgentAccessWithOptions([]string{"disable", "--yes"}, opts, &out); err != nil {
		t.Fatalf("disable --yes failed: %v", err)
	}
	if _, err := os.Stat(policyPath); err != nil {
		t.Fatalf("disable --yes should preserve policy: %v", err)
	}

	// Disable --purge-policy --yes removes policy.
	out.Reset()
	if err := runControllerAgentAccessWithOptions([]string{"disable", "--purge-policy", "--yes"}, opts, &out); err != nil {
		t.Fatalf("disable --purge-policy --yes failed: %v", err)
	}
	if _, err := os.Stat(policyPath); !os.IsNotExist(err) {
		t.Fatalf("disable --purge-policy --yes did not remove policy: %v", err)
	}
}
