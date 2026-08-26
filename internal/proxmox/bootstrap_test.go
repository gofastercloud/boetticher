package proxmox

import (
	"context"
	"strings"
	"testing"
)

type fakeRunner struct {
	address string
	user    string
	command string
	output  []byte
}

func (f *fakeRunner) Run(_ context.Context, address, user, command string) ([]byte, error) {
	f.address, f.user, f.command = address, user, command
	return f.output, nil
}

func TestInstallOperatorKeyUsesSafeConstantRemoteCommand(t *testing.T) {
	runner := &fakeRunner{}
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample operator"
	if err := InstallOperatorKey(context.Background(), runner, "192.0.2.10", "root", key); err != nil {
		t.Fatal(err)
	}
	if runner.address != "192.0.2.10" || runner.user != "root" || !strings.Contains(runner.command, "authorized_keys") {
		t.Fatalf("unexpected bootstrap request: %#v", runner)
	}
	if strings.Contains(runner.command, "StrictHostKeyChecking=no") || strings.Contains(runner.command, "password") {
		t.Fatalf("bootstrap command weakened SSH or accepted a password argument: %s", runner.command)
	}
}

func TestCreateScopedCredentialsCapturesOnlyReturnedSecret(t *testing.T) {
	runner := &fakeRunner{output: []byte(`{"value":"opaque-token-secret"}`)}
	secret, err := CreateScopedCredentials(context.Background(), runner, "192.0.2.10", "root", "labadmin@pve", "labinabox")
	if err != nil || secret != "opaque-token-secret" {
		t.Fatalf("CreateScopedCredentials() = %q, %v", secret, err)
	}
	if strings.Contains(runner.command, "opaque-token-secret") {
		t.Fatal("returned token secret was interpolated into the remote command")
	}
}
