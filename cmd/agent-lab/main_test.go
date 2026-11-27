package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunHelpSucceedsWithoutConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "agent-lab") {
		t.Fatalf("expected usage in stdout, got: %q", stdout.String())
	}
}
