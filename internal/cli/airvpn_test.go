package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadAirVPNAPIKeyTrimsFileWhitespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("  provider-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readAirVPNAPIKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "provider-key" {
		t.Fatalf("readAirVPNAPIKey() = %q, want trimmed key", got)
	}
}
