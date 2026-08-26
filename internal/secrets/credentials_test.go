package secrets

import (
	"context"
	"io"
	"strings"
	"testing"
)

type credentialRunner struct {
	command string
	value   []byte
}

func (r *credentialRunner) RunWithStdin(_ context.Context, _ string, _ string, command string, stdin io.Reader) ([]byte, error) {
	r.command = command
	data, err := io.ReadAll(stdin)
	r.value = data
	return nil, err
}

func TestCredentialProjectionContainsNoSecretValues(t *testing.T) {
	synthetic := "synthetic-secret-never-in-output"
	spec := CredentialSpec{Name: "ddns-tsig", Unit: "kea-dhcp-ddns-server.service", StorePath: "/var/lib/boetticher/credentials/ddns-tsig.cred"}
	content, err := UnitDropIn([]CredentialSpec{spec})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(content, synthetic) {
		t.Fatal("credential value entered the projection")
	}
	argv, err := InstallCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(argv, " "), synthetic) {
		t.Fatal("credential value entered argv")
	}
}

func TestCredentialNamesCannotBeSharedAcrossUnits(t *testing.T) {
	_, err := UnitDropIn([]CredentialSpec{
		{Name: "same", Unit: "one.service", StorePath: "/var/lib/boetticher/credentials/one"},
		{Name: "same", Unit: "two.service", StorePath: "/var/lib/boetticher/credentials/two"},
	})
	if err == nil {
		t.Fatal("credential was shared across units")
	}
}

func TestInstallCredentialStreamsValueOutsideCommand(t *testing.T) {
	value := []byte("synthetic-secret-never-in-argv")
	runner := &credentialRunner{}
	spec := CredentialSpec{Name: "ddns-tsig", Unit: "kea-dhcp-ddns-server.service", StorePath: "/var/lib/boetticher/credentials/ddns-tsig.cred"}
	if err := InstallCredential(context.Background(), runner, "192.0.2.10", "root", spec, value); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(runner.command, string(value)) {
		t.Fatal("credential value entered the remote command")
	}
	if string(runner.value) != string(value) {
		t.Fatalf("stdin value = %q, want fixture value", runner.value)
	}
}

func TestUnitDropInsUseServiceSectionsPerUnit(t *testing.T) {
	dropins, err := UnitDropIns([]CredentialSpec{
		{Name: "one", Unit: "one.service", StorePath: "/var/lib/boetticher/credentials/one"},
		{Name: "two", Unit: "two.service", StorePath: "/var/lib/boetticher/credentials/two"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(dropins["one.service"], "[Service]\n") || strings.Contains(dropins["one.service"], "two") {
		t.Fatalf("unexpected one.service drop-in: %q", dropins["one.service"])
	}
}

func TestCredentialPathsCannotEscapeProtectedStore(t *testing.T) {
	_, err := UnitDropIns([]CredentialSpec{{Name: "bad", Unit: "bad.service", StorePath: "/var/lib/boetticher/credentials/../outside"}})
	if err == nil {
		t.Fatal("credential path traversal was accepted")
	}
}
