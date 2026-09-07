package firewallmodule

import (
	"context"
	"strings"
	"testing"
)

func TestPasswordHashDoesNotReturnPlainCredential(t *testing.T) {
	hash, err := PasswordHash(context.Background(), "phase4a-test-credential")
	if err != nil {
		t.Skipf("openssl -6 is unavailable in this test environment: %v", err)
	}
	if !strings.HasPrefix(hash, "$6$") || strings.Contains(hash, "phase4a-test-credential") {
		t.Fatalf("unexpected provider password hash: %q", hash)
	}
}
