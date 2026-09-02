package sshconfig

import (
	"os"
	"path/filepath"
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
		"ChannelTimeout direct-tcpip=10",
		"Host lab-fw-01 lab-fw-01.lab.home.arpa firewall",
		"Host lab-dns-01 lab-dns-01.lab.home.arpa dns01 dns",
		"HostName 10.10.10.10",
		"ConnectTimeout 10",
		"ControlMaster auto",
		"ControlPersist 60",
		"ControlPath ~/.ssh/boetticher-control-%C",
		"ProxyJump lab-bastion",
		"HostKeyAlias lab-dns-01.lab.home.arpa",
		"StrictHostKeyChecking yes",
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

func TestRenderWithKnownHostsUsesSiteScopedTrustFile(t *testing.T) {
	s := model.NewDefaultSite("installation", "age1example")
	s.TestedVersions.Gateway = model.QualifiedGatewayImage
	s.BootstrapAddress = "192.0.2.10"
	knownHosts := filepath.Join(t.TempDir(), "generated", "ssh", "known_hosts")
	content, err := RenderWithKnownHosts(s, time.Unix(0, 0), knownHosts)
	if err != nil {
		t.Fatal(err)
	}
	expected := `UserKnownHostsFile "` + knownHosts + `"`
	if !strings.Contains(content, expected) {
		t.Fatalf("site-scoped SSH trust file missing %q: %s", expected, content)
	}
	if strings.Contains(content, "StrictHostKeyChecking no") || strings.Contains(content, "UserKnownHostsFile /dev/null") {
		t.Fatal("site-scoped SSH configuration weakened host-key verification")
	}
}

func TestRenderDirectPinsFreshApplianceTransport(t *testing.T) {
	content, err := RenderDirect("192.0.2.50", "piadmin", "/tmp/operator key", "/tmp/kiosk known_hosts", 22)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"Host boetticher-kiosk",
		"HostName 192.0.2.50",
		"Port 22",
		"User piadmin",
		"StrictHostKeyChecking yes",
		`UserKnownHostsFile "/tmp/kiosk known_hosts"`,
		`IdentityFile "/tmp/operator key"`,
		"IdentitiesOnly yes",
		"ForwardAgent no",
		"RequestTTY no",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("direct SSH configuration missing %q: %s", expected, content)
		}
	}
	if strings.Contains(content, "ProxyCommand") || strings.Contains(content, "StrictHostKeyChecking no") {
		t.Fatal("direct SSH configuration weakened or redirected transport")
	}
}

func TestRenderDirectRejectsUnsafeTransportInputs(t *testing.T) {
	for _, address := range []string{"pi.example", "192.0.2.50:22", "2001:db8::50", "192.0.2.050"} {
		if _, err := RenderDirect(address, "pi", "/tmp/key", "/tmp/known_hosts", 22); err == nil {
			t.Fatalf("non-canonical address %q was accepted", address)
		}
	}
	for _, user := range []string{"pi;id", "pi user", "1pi"} {
		if _, err := RenderDirect("192.0.2.50", user, "/tmp/key", "/tmp/known_hosts", 22); err == nil {
			t.Fatalf("unsafe SSH user %q was accepted", user)
		}
	}
	if _, err := RenderDirect("192.0.2.50", "pi", "/tmp/key\nProxyCommand sh -c id", "/tmp/known_hosts", 22); err == nil {
		t.Fatal("control-character SSH identity path was accepted")
	}
}

func TestRenderIncludesRetainedProductOwnedGuestForCleanup(t *testing.T) {
	s := model.NewDefaultSite("installation", "age1example")
	s.TestedVersions.Gateway = model.QualifiedGatewayImage
	s.BootstrapAddress = "192.0.2.10"
	s.RetainedModules = []model.RetainedModule{{
		Module: "tailnet-router", Disposition: "retained",
		Guests: []model.Component{{Name: "lab-tailnet-01", Hostname: "lab-tailnet-01", Zone: "TRANSIT", Address: "10.10.5.10", VMID: 200, Module: "tailnet-router", ProductOwned: true, SSHManaged: true, SSHUser: model.DefaultAdminSSHUser, SSHPort: 22, Tags: []string{model.TagBoetticher, model.TagManaged, model.TagModule, "module-tailnet-router", model.ModuleOwnershipTag("tailnet-router")}}},
	}}
	content, err := RenderWithKnownHosts(s, time.Unix(0, 0), filepath.Join(t.TempDir(), "known_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(content, "Host lab-tailnet-01 lab-tailnet-01.lab.home.arpa") {
		t.Fatalf("retained guest SSH identity is absent:\n%s", content)
	}
}

func TestRenderBastionPolicyIncludesRetainedGuestForCleanup(t *testing.T) {
	s := model.NewDefaultSite("installation", "age1example")
	s.RetainedModules = []model.RetainedModule{{
		Module: "tailnet-router", Disposition: "retained",
		Guests: []model.Component{{Name: "lab-tailnet-01", Hostname: "lab-tailnet-01", Zone: "TRANSIT", Address: "10.10.5.10", VMID: 200, Module: "tailnet-router", ProductOwned: true, SSHManaged: true, JumpAllowed: true, Tags: []string{model.TagBoetticher, model.TagManaged, model.TagModule, "module-tailnet-router", model.ModuleOwnershipTag("tailnet-router")}}},
	}}
	content, err := RenderBastionPolicy(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(content, "10.10.5.10:22") {
		t.Fatalf("retained guest was not added to the bastion allowlist:\n%s", content)
	}
}

func TestRenderQuotesSSHPathsAndRejectsControlCharacters(t *testing.T) {
	s := model.NewDefaultSite("installation", "age1example")
	s.TestedVersions.Gateway = model.QualifiedGatewayImage
	s.BootstrapAddress = "192.0.2.10"
	s.SSHIdentityFile = "/tmp/operator key"
	content, err := RenderWithKnownHosts(s, time.Unix(0, 0), "/tmp/site known_hosts")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(content, `IdentityFile "/tmp/operator key"`) || !strings.Contains(content, `UserKnownHostsFile "/tmp/site known_hosts"`) {
		t.Fatalf("SSH paths were not quoted: %s", content)
	}
	s.SSHIdentityFile = "/tmp/key\nProxyCommand sh -c id"
	if _, err := Render(s, time.Unix(0, 0)); err == nil || !strings.Contains(err.Error(), "control characters") {
		t.Fatalf("control-character identity path was accepted: %v", err)
	}
	unsafeKnownHostsSite := model.NewDefaultSite("installation", "age1example")
	unsafeKnownHostsSite.TestedVersions.Gateway = model.QualifiedGatewayImage
	unsafeKnownHostsSite.BootstrapAddress = "192.0.2.10"
	if _, err := RenderWithKnownHosts(unsafeKnownHostsSite, time.Unix(0, 0), "/tmp/known\nHost *\n  ProxyCommand sh -c id"); err == nil || !strings.Contains(err.Error(), "control characters") {
		t.Fatalf("control-character known-hosts path was accepted: %v", err)
	}
}

func TestRemoveHostKeyRemovesOnlyTheExactGeneratedAlias(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	content := "# generated\nlab-dns-01.lab.home.arpa ssh-ed25519 AAAAold\nlab-dns-02.lab.home.arpa ssh-ed25519 AAAAkeep\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveHostKey(path, "lab-dns-01.lab.home.arpa"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "lab-dns-01.lab.home.arpa") || !strings.Contains(text, "lab-dns-02.lab.home.arpa") || !strings.Contains(text, "# generated") {
		t.Fatalf("known-hosts content after exact removal = %q", text)
	}
}

func TestAddHostKeyPinsIndependentIdentityAndRejectsChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := AddHostKey(path, "lab-dns-01.lab.home.arpa", key); err != nil {
		t.Fatal(err)
	}
	if err := AddHostKey(path, "lab-dns-01.lab.home.arpa", key+" comment"); err != nil {
		t.Fatalf("same host key was not idempotent: %v", err)
	}
	changed := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := AddHostKey(path, "lab-dns-01.lab.home.arpa", changed); err == nil {
		t.Fatal("changed host key was accepted")
	}
}

func TestReadAndCopyKnownHostKeyBindsBootstrapAlias(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source-known-hosts")
	target := filepath.Join(t.TempDir(), "generated", "known_hosts")
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := os.WriteFile(source, []byte("lab-proxmox-01 "+key+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadHostKey(source, "lab-proxmox-01")
	if err != nil || got != key {
		t.Fatalf("ReadHostKey() = %q, %v", got, err)
	}
	if err := AddKnownHostKey(target, "lab-proxmox-01", got); err != nil {
		t.Fatal(err)
	}
	if copied, err := ReadHostKey(target, "lab-proxmox-01"); err != nil || copied != key {
		t.Fatalf("copied host key = %q, %v", copied, err)
	}
}

func TestValidateBootstrapAddressRequiresCanonicalIPv4(t *testing.T) {
	for _, address := range []string{"proxmox.example", "192.0.2.10:8006", " 192.0.2.10", "2001:db8::10", "192.0.2.010"} {
		if err := ValidateBootstrapAddress(address); err == nil {
			t.Fatalf("non-canonical bootstrap address %q was accepted", address)
		}
	}
	if err := ValidateBootstrapAddress("192.0.2.10"); err != nil {
		t.Fatalf("canonical bootstrap address was rejected: %v", err)
	}
}

func TestValidateExecutionConfigRejectsCommandDirectives(t *testing.T) {
	for _, directive := range []string{"ProxyCommand", `"ProxyCommand"`} {
		path := filepath.Join(t.TempDir(), "boetticher.conf")
		if err := os.WriteFile(path, []byte("Host lab-dns-01\n    "+directive+" sh -c id\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := ValidateExecutionConfig(path); err == nil {
			t.Fatalf("%s was accepted in an execution configuration", directive)
		}
	}
}

func TestBastionPolicyOnlyAllowsModelledHosts(t *testing.T) {
	s := model.NewDefaultSite("installation", "age1example")
	s.TestedVersions.Gateway = model.QualifiedGatewayImage
	content, err := RenderBastionPolicy(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(content, "PermitOpen 10.10.10.10:22") || !strings.Contains(content, "10.10.10.30:443") || strings.Contains(content, "10.10.50.") {
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

func TestBastionPolicyAllowsLiteLLMHTTPSForControllerCanary(t *testing.T) {
	enabled := true
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	config.Modules.LiteLLM = &model.LiteLLMModuleConfig{
		Enabled: &enabled,
		Upstreams: []model.LiteLLMUpstreamConfig{{
			Name: "provider", BaseURL: "https://provider.example/v1", APIKeySecret: "provider_api_key",
		}},
		Models: []model.LiteLLMModelConfig{{Alias: "operations", Upstream: "provider", Model: "provider/model"}},
	}
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := RenderBastionPolicy(site)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(policy, "10.10.20.60:443") {
		t.Fatalf("LiteLLM HTTPS endpoint is missing from the restricted bastion policy: %s", policy)
	}
}
