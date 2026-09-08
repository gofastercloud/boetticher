package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPushoverTestRequiresApprovalBeforeNetworkSend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pushover.key")
	key := "0123456789ABCDEFGHIJklmnopqrst"
	if err := os.WriteFile(path, []byte(key+":"+key+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	err := runObservabilityAlerts([]string{"pushover", "test", "--credentials-file", path}, strings.NewReader("n\n"), &out, &errOut)
	if err == nil || !strings.Contains(err.Error(), "cancelled") || strings.Contains(out.String(), "SENT") {
		t.Fatalf("Pushover test bypassed approval: err=%v output=%s", err, out.String())
	}
}

func TestReadPushoverCredentialsFileBoundsAndNoNewline(t *testing.T) {
	dir := t.TempDir()
	key := "0123456789ABCDEFGHIJklmnopqrst"
	path := filepath.Join(dir, "credentials")
	if err := os.WriteFile(path, []byte(key+":"+key), 0600); err != nil {
		t.Fatal(err)
	}
	credentials, err := readPushoverCredentialsFile(path)
	if err != nil || credentials.User != key || credentials.Token != key {
		t.Fatalf("valid no-newline credentials rejected: credentials=%+v err=%v", credentials, err)
	}
	link := filepath.Join(dir, "credentials-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readPushoverCredentialsFile(link); err == nil {
		t.Fatal("symlink credentials file accepted")
	}
	oversized := filepath.Join(dir, "oversized")
	if err := os.WriteFile(oversized, []byte(strings.Repeat("x", 64*1024+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPushoverCredentialsFile(oversized); err == nil {
		t.Fatal("oversized credentials file accepted")
	}
}
