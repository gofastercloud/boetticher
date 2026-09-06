package host

import (
	"context"
	"strings"
	"testing"
)

func TestValidateHostKeyRequiresIPv4AndNormalizesKey(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA trusted"
	got, err := ValidateHostKey("192.0.2.10", key)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "192.0.2.10 ssh-ed25519 ") || strings.Contains(got, " trusted") {
		t.Fatalf("normalized host key = %q", got)
	}
	for _, address := range []string{"proxmox.example", "2001:db8::10", ""} {
		if _, err := ValidateHostKey(address, key); err == nil {
			t.Fatalf("ValidateHostKey(%q) unexpectedly passed", address)
		}
	}
}

func TestParseNodesAcceptsArrayAndDataEnvelope(t *testing.T) {
	for _, input := range []string{
		`[{"node":"pve","status":"online","type":"node"}]`,
		`{"data":[{"node":"pve","status":"online","type":"node"}]}`,
	} {
		nodes, err := parseNodes([]byte(input))
		if err != nil || len(nodes) != 1 || nodes[0].Node != "pve" {
			t.Fatalf("parseNodes(%s) = %#v, %v", input, nodes, err)
		}
	}
	if _, err := parseNodes([]byte(`{"not_nodes":true}`)); err == nil {
		t.Fatal("malformed node listing was accepted")
	}
}

func TestSupportedVersionRejectsUnknownMajor(t *testing.T) {
	for _, test := range []struct {
		version string
		want    bool
	}{
		{"pve-manager/9.2.2/b9984c6d90a4bd80", true},
		{"pve-manager/8.4.1/foo", true},
		{"pve-manager/7.4.17/foo", false},
		{"not-pve", false},
	} {
		if got := supportedVersion(test.version); got != test.want {
			t.Errorf("supportedVersion(%q) = %v, want %v", test.version, got, test.want)
		}
	}
}

func TestTransportArgsAreStrictAndRootOnly(t *testing.T) {
	transport := Transport{Address: "192.0.2.10", User: "root", Identity: PrivateKeyPath, KnownHosts: KnownHostsPath}
	args, err := transport.Args("hostname")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, required := range []string{"BatchMode=yes", "StrictHostKeyChecking=yes", "IdentitiesOnly=yes", "PasswordAuthentication=no", "KbdInteractiveAuthentication=no", "ControlMaster=no", "ControlPath=none", "ForwardAgent=no", "ForwardX11=no", "root@192.0.2.10", "hostname"} {
		if !strings.Contains(joined, required) {
			t.Errorf("transport args missing %q: %s", required, joined)
		}
	}
	if _, err := (Transport{Address: "192.0.2.10", User: "pi", Identity: PrivateKeyPath, KnownHosts: KnownHostsPath}).Args("hostname"); err == nil {
		t.Fatal("non-root transport was accepted")
	}
	if _, err := (Transport{Address: "192.0.2.10", User: "root", Identity: PrivateKeyPath, KnownHosts: KnownHostsPath}).Run(context.Background(), ""); err == nil {
		t.Fatal("empty remote command was accepted")
	}
}
