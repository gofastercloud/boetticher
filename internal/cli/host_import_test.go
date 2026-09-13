package cli

import (
	"strings"
	"testing"
)

func TestRunHostImportHostKeyConsumesDocumentedFlagOnlyArguments(t *testing.T) {
	err := runHost([]string{"import-host-key", "--address", "192.168.4.5", "--key", "ssh-ed25519 invalid"}, nil, nil, nil)
	if err == nil || strings.Contains(err.Error(), "usage: boetticher host import-host-key") {
		t.Fatalf("flag-only import dispatch did not consume documented arguments: %v", err)
	}
}
