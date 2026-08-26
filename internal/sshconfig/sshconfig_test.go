package sshconfig

import (
	"strings"
	"testing"
	"time"

	"github.com/dave/labinabox/internal/model"
)

func TestRenderUsesBastionAndCanonicalHostKey(t *testing.T) {
	s := model.NewDefaultSite("installation", "age1example")
	s.TestedVersions.OPNsense = model.QualifiedOPNsense
	s.BootstrapAddress = "192.0.2.10"
	s.SSHIdentityFile = "~/.ssh/id_ed25519"
	content, err := Render(s, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"Host lab-bastion",
		"Host lab-dns-01 lab-dns-01.lab.home.arpa dns01 dns",
		"HostName 10.10.20.10",
		"ProxyJump lab-bastion",
		"HostKeyAlias lab-dns-01.lab.home.arpa",
		"IdentityFile ",
		"IdentitiesOnly yes",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("generated SSH config missing %q", expected)
		}
	}
	if strings.Contains(content, "StrictHostKeyChecking no") {
		t.Error("generated SSH config weakened host-key verification")
	}
}

func TestBastionPolicyOnlyAllowsModelledHosts(t *testing.T) {
	s := model.NewDefaultSite("installation", "age1example")
	s.TestedVersions.OPNsense = model.QualifiedOPNsense
	content, err := RenderBastionPolicy(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(content, "PermitOpen 10.10.20.10:22") || strings.Contains(content, "10.10.50.") {
		t.Fatalf("unexpected bastion destination policy: %s", content)
	}
}
