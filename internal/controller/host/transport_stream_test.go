package host

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// streamingTransport binds a fake ssh that runs the remote command locally,
// so the line-streaming path is exercised end to end without a Host.
func streamingTransport(t *testing.T) Transport {
	t.Helper()
	directory := t.TempDir()
	identity, knownHosts, ssh := filepath.Join(directory, "id"), filepath.Join(directory, "known_hosts"), filepath.Join(directory, "ssh")
	for _, path := range []string{identity, knownHosts} {
		if err := os.WriteFile(path, []byte("test\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	script := "#!/bin/sh\nfor last; do :; done\nexec /bin/sh -c \"$last\"\n"
	if err := os.WriteFile(ssh, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	return Transport{Address: "192.0.2.10", User: "root", Identity: identity, KnownHosts: knownHosts, SSHPath: ssh, Timeout: 10 * time.Second}
}

func TestTransportRunLinesDeliversLinesBeforeExit(t *testing.T) {
	transport := streamingTransport(t)
	start := time.Now()
	var lines []string
	var arrivals []time.Duration
	result, err := transport.RunLines(context.Background(), "printf 'first\\n'; sleep 0.5; printf 'second\\n'; printf 'oops\\n' >&2", 64, func(line []byte) {
		lines = append(lines, string(line))
		arrivals = append(arrivals, time.Since(start))
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(lines, ",") != "first,second" {
		t.Fatalf("lines = %#v", lines)
	}
	if arrivals[1]-arrivals[0] < 400*time.Millisecond {
		t.Fatalf("first line was buffered until exit: arrivals %v", arrivals)
	}
	if len(result.Stdout) != 0 || strings.TrimSpace(string(result.Stderr)) != "oops" {
		t.Fatalf("result = %#v", result)
	}
}

func TestTransportRunLinesReportsFailureAndOversizedLines(t *testing.T) {
	transport := streamingTransport(t)
	var lines []string
	result, err := transport.RunLines(context.Background(), "printf 'partial\\n'; echo broken >&2; exit 3", 64, func(line []byte) { lines = append(lines, string(line)) })
	if err == nil || result.ExitCode != 3 || !strings.Contains(err.Error(), "broken") || len(lines) != 1 {
		t.Fatalf("failed command: lines=%#v result=%#v err=%v", lines, result, err)
	}
	start := time.Now()
	_, err = transport.RunLines(context.Background(), "head -c 200 /dev/zero | tr '\\0' x; echo; sleep 5", 64, func([]byte) {})
	if err == nil || !strings.Contains(err.Error(), "output") {
		t.Fatalf("oversized line accepted: %v", err)
	}
	if time.Since(start) > 4*time.Second {
		t.Fatal("oversized line did not terminate the session promptly")
	}
	if _, err := transport.RunLines(context.Background(), "true", 0, func([]byte) {}); err == nil {
		t.Fatal("unbounded streaming was accepted")
	}
}

func TestTransportRunLinesHonoursTimeout(t *testing.T) {
	transport := streamingTransport(t)
	transport.Timeout = 300 * time.Millisecond
	start := time.Now()
	_, err := transport.RunLines(context.Background(), "printf 'tick\\n'; sleep 5", 64, func([]byte) {})
	if err == nil || !strings.Contains(err.Error(), "timed out") || time.Since(start) > 3*time.Second {
		t.Fatalf("timeout not enforced: %v after %s", err, time.Since(start))
	}
}
