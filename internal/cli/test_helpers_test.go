package cli

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func writeTestAgeIdentity(t *testing.T) (string, string) {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(path, []byte(identity.String()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return path, identity.Recipient().String()
}
