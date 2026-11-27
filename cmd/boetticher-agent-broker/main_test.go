package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/agentbroker"
)

func TestRunReadsSSHOriginalCommandAndAudits(t *testing.T) {
	env := map[string]string{
		"SSH_ORIGINAL_COMMAND":         "boetticher host status --details",
		"SUDO_USER":                    "boetticher-agent",
		"BOETTICHER_AGENT_KEY_COMMENT": "agent-mac",
	}
	getenv := func(k string) string { return env[k] }

	var gotBinary string
	var gotArgs []string
	var stdout, stderr, audit bytes.Buffer
	missingPolicy := filepath.Join(t.TempDir(), "agent-policy.yml")

	code := run(
		context.Background(),
		getenv,
		strings.NewReader(""),
		&stdout,
		&stderr,
		&audit,
		agentbroker.DefaultBoetticherBinary,
		missingPolicy,
		func(os.FileInfo) error { return nil },
		func(_ context.Context, binary string, args []string, _ io.Reader, out, _ io.Writer) (int, error) {
			gotBinary = binary
			gotArgs = append([]string(nil), args...)
			_, _ = io.WriteString(out, "host ok\n")
			return 0, nil
		},
	)
	if code != 0 {
		t.Fatalf("run() = %d, want 0 (stderr=%s)", code, stderr.String())
	}
	if gotBinary != agentbroker.DefaultBoetticherBinary {
		t.Fatalf("binary = %q, want %q", gotBinary, agentbroker.DefaultBoetticherBinary)
	}
	if !reflect.DeepEqual(gotArgs, []string{"host", "status", "--details"}) {
		t.Fatalf("args = %v", gotArgs)
	}

	var rec agentbroker.AuditRecord
	if err := json.Unmarshal(bytes.TrimSpace(audit.Bytes()), &rec); err != nil {
		t.Fatalf("unmarshal audit: %v", err)
	}
	if rec.Decision != "allow" || rec.User != "boetticher-agent" || rec.KeyComment != "agent-mac" || rec.ExitCode != 0 {
		t.Fatalf("unexpected audit record: %+v", rec)
	}
}

func TestRunDeniesEmptyOrHardDeniedCommand(t *testing.T) {
	env := map[string]string{
		"SSH_ORIGINAL_COMMAND": "boetticher host reboot --yes",
		"USER":                 "boetticher-agent",
	}
	getenv := func(k string) string { return env[k] }

	executed := false
	var stdout, stderr, audit bytes.Buffer
	missingPolicy := filepath.Join(t.TempDir(), "agent-policy.yml")

	code := run(
		context.Background(),
		getenv,
		strings.NewReader(""),
		&stdout,
		&stderr,
		&audit,
		agentbroker.DefaultBoetticherBinary,
		missingPolicy,
		func(os.FileInfo) error { return nil },
		func(_ context.Context, _ string, _ []string, _ io.Reader, _, _ io.Writer) (int, error) {
			executed = true
			return 0, nil
		},
	)
	if code == 0 {
		t.Fatal("expected non-zero exit code for hard-denied command")
	}
	if executed {
		t.Fatal("executor must not run for hard-denied command")
	}
	var rec agentbroker.AuditRecord
	if err := json.Unmarshal(bytes.TrimSpace(audit.Bytes()), &rec); err != nil {
		t.Fatalf("unmarshal audit: %v", err)
	}
	if rec.Decision != "deny" || rec.User != "boetticher-agent" {
		t.Fatalf("unexpected audit record: %+v", rec)
	}
}
