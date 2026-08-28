package sshconfig

import (
	"strings"
	"testing"
	"time"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
)

func TestRenderUsesBastionAndCanonicalHostKey(t *testing.T) {
	s := model.NewDefaultSite("installation", "age1example")
	s.TestedVersions.Gateway = model.QualifiedGatewayImage
	s.BootstrapAddress = "192.0.2.10"
	s.SSHIdentityFile = "~/.ssh/id_ed25519"
	content, err := Render(s, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"Host lab-bastion",
		"Host lab-fw-01 lab-fw-01.lab.home.arpa firewall",
		"Host lab-dns-01 lab-dns-01.lab.home.arpa dns01 dns",
		"HostName 10.10.10.10",
		"ProxyJump lab-bastion",
		"HostKeyAlias lab-dns-01.lab.home.arpa",
		"StrictHostKeyChecking accept-new",
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
	s.TestedVersions.Gateway = model.QualifiedGatewayImage
	content, err := RenderBastionPolicy(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(content, "PermitOpen 10.10.10.10:22") || strings.Contains(content, "10.10.50.") {
		t.Fatalf("unexpected bastion destination policy: %s", content)
	}
}

func TestRenderComposedSiteIncludesDeclaredModuleGuests(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	site.BootstrapAddress = "192.0.2.10"
	content, err := Render(site, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"Host lab-fw-01 lab-fw-01.lab.home.arpa",
		"Host lab-dns-01 lab-dns-01.lab.home.arpa dns01 dns",
		"Host lab-dns-02 lab-dns-02.lab.home.arpa dns02",
		"Host lab-log-01 lab-log-01.lab.home.arpa logs",
		"Host lab-monitor-01 lab-monitor-01.lab.home.arpa monitor",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("composed SSH configuration missing %q", expected)
		}
	}
	policy, err := RenderBastionPolicy(site)
	if err != nil {
		t.Fatal(err)
	}
	for _, destination := range []string{"10.10.99.1:22", "10.10.10.10:22", "10.10.10.20:22", "10.10.10.20:443", "10.10.10.40:22"} {
		if !strings.Contains(policy, destination) {
			t.Errorf("composed bastion policy missing module destination %q", destination)
		}
	}
}
