package secrets

import (
	"strings"
	"testing"
)

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
