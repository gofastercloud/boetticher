package cli

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/dns"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
)

type credentialDeploymentRunner struct {
	commands  []string
	users     []string
	values    []string
	output    []byte
	runOutput []byte
}

func (r *credentialDeploymentRunner) Run(_ context.Context, _ string, user string, command string) ([]byte, error) {
	r.commands = append(r.commands, command)
	r.users = append(r.users, user)
	return r.runOutput, nil
}

func (r *credentialDeploymentRunner) RunWithStdin(_ context.Context, _ string, user string, command string, stdin io.Reader) ([]byte, error) {
	r.commands = append(r.commands, command)
	r.users = append(r.users, user)
	data, err := io.ReadAll(stdin)
	if err == nil {
		r.values = append(r.values, string(data))
	}
	return r.output, err
}

func TestDeploymentCredentialProjectionContainsOnlyEncryptedPaths(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := deploymentCredentialBindings(site)
	if err != nil {
		t.Fatal(err)
	}
	dropIns, err := credentialDropIns(bindings)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dropIns["lab-fw-01"]["kea-dhcp-ddns-server.service"], "LoadCredentialEncrypted=kea-ddns-tsig:/var/lib/boetticher/credentials/kea-ddns-tsig.cred") {
		t.Fatalf("firewall credential projection is incomplete: %#v", dropIns)
	}
	if strings.Contains(strings.Join([]string{dropIns["lab-fw-01"]["kea-dhcp-ddns-server.service"], dropIns["lab-monitor-01"]["pulse.service"]}, "\n"), "synthetic-secret") {
		t.Fatal("credential projection contains a secret value")
	}
	if !strings.Contains(dropIns["lab-monitor-01"]["pulse.service"], "LoadCredentialEncrypted=pulse-admin-password:/var/lib/boetticher/credentials/pulse-admin-password.cred") {
		t.Fatalf("Pulse administrative credential projection is incomplete: %#v", dropIns)
	}
	agentBindings, err := monitoringAgentCredentialBindings(site)
	if err != nil {
		t.Fatal(err)
	}
	if len(agentBindings) != 1 || agentBindings[0].Guest != model.LogicalProxmoxIdentity {
		t.Fatalf("default Pulse agent bindings = %#v, want only the Proxmox host", agentBindings)
	}
	agentDropIns, err := credentialDropIns(agentBindings)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(agentDropIns[model.LogicalProxmoxIdentity]["pulse-agent.service"], "LoadCredentialEncrypted=pulse-agent-token:/var/lib/boetticher/credentials/pulse-agent-token.cred") {
		t.Fatalf("Pulse agent credential projection is incomplete: %#v", agentDropIns)
	}
}

func TestFirstPartyModuleCredentialsUseEphemeralSystemdPaths(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	tailnetEnabled, litellmEnabled := true, true
	config.Modules.TailnetRouter = &model.ToggleModuleConfig{Enabled: &tailnetEnabled}
	config.Modules.LiteLLM = &model.LiteLLMModuleConfig{
		Enabled:   &litellmEnabled,
		Upstreams: []model.LiteLLMUpstreamConfig{{Name: "openrouter", BaseURL: "https://openrouter.ai/api/v1", APIKeySecret: "openrouter_api_key"}},
		Models:    []model.LiteLLMModelConfig{{Alias: "selected-alias", Upstream: "openrouter", Model: "selected/openrouter-model"}},
	}
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := deploymentCredentialBindings(site)
	if err != nil {
		t.Fatal(err)
	}
	dropIns, err := credentialDropIns(bindings)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dropIns["lab-tailnet-01"]["tailscaled.service"], "LoadCredentialEncrypted=tailscale-auth-key:/var/lib/boetticher/credentials/tailscale-auth-key.cred") {
		t.Fatalf("Tailscale credential projection is incomplete: %#v", dropIns)
	}
	if !strings.Contains(dropIns["lab-litellm-01"]["litellm.service"], "openrouter-api-key:/var/lib/boetticher/credentials/openrouter-api-key.cred") {
		t.Fatalf("LiteLLM credential projection is incomplete: %#v", dropIns)
	}
	if strings.Contains(strings.Join([]string{dropIns["lab-tailnet-01"]["tailscaled.service"], dropIns["lab-litellm-01"]["litellm.service"]}, "\n"), "synthetic-secret") {
		t.Fatal("module credential projection contains a secret value")
	}
}

func TestStreamDeckUsesSharedPulseTokenOnlyInPostPulseProjection(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	enabled := true
	config.Modules.StreamDeck = &model.ToggleModuleConfig{Enabled: &enabled}
	config.USBExports = []model.USBExportBinding{{Module: "streamdeck", Requirement: "display", Port: "1-2.5", VendorID: "0fd9", ProductID: "006d"}}
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := deploymentCredentialBindings(site)
	if err != nil {
		t.Fatal(err)
	}
	for _, binding := range initial {
		if binding.Guest == "lab-streamdeck-01" {
			t.Fatal("StreamDeck credential was included before Pulse read-token validation")
		}
	}
	bindings, err := streamDeckCredentialBindings(site)
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 1 || bindings[0].SecretKey != "pulse_api_token" || bindings[0].Spec.Unit != "streamdeck-status.service" {
		t.Fatalf("unexpected StreamDeck credential binding: %#v", bindings)
	}
	dropIns, err := credentialDropIns(bindings)
	if err != nil {
		t.Fatal(err)
	}
	projection := dropIns["lab-streamdeck-01"]["streamdeck-status.service"]
	if !strings.Contains(projection, "LoadCredentialEncrypted=pulse-token:/var/lib/boetticher/credentials/streamdeck-pulse-token.cred") || strings.Contains(projection, "synthetic-secret") {
		t.Fatalf("StreamDeck credential projection is incomplete or leaked a value: %q", projection)
	}
}

func TestCredentialNameMatchesAnsibleNormalizationForValidReferences(t *testing.T) {
	if got := credentialName("OpenRouter__api_key."); got != "openrouter--api-key-" {
		t.Fatalf("credential name normalization = %q", got)
	}
}

func TestCredentialInstallationStreamsValuesOutsideCommands(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := deploymentCredentialBindings(site)
	if err != nil {
		t.Fatal(err)
	}
	runner := &credentialDeploymentRunner{}
	secret := "synthetic-secret-never-in-command"
	if err := installCredentialsForGuest(context.Background(), runner, "lab-fw-01", bindings, map[string]string{"firewall-ddns-tsig": secret}); err != nil {
		t.Fatal(err)
	}
	if len(runner.values) != 1 || runner.values[0] != secret {
		t.Fatalf("credential value was not streamed exactly once: %#v", runner.values)
	}
	for _, command := range runner.commands {
		if strings.Contains(command, secret) {
			t.Fatalf("credential value entered remote command: %s", command)
		}
		if strings.Contains(command, "sudo") {
			t.Fatalf("credential installation retained a sudo dependency: %s", command)
		}
	}
	for _, user := range runner.users {
		if user != "root" {
			t.Fatalf("credential installation used durable user %q", user)
		}
	}
}

func TestPowerDNSExceptionStreamsProtectedBackendSQL(t *testing.T) {
	plan, err := dns.PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	runner := &credentialDeploymentRunner{output: []byte("1\n")}
	secret := "synthetic-powerdns-secret"
	needsRestart, err := installPowerDNSTSIG(context.Background(), runner, "10.10.10.10", plan, secret)
	if err != nil {
		t.Fatal(err)
	}
	if !needsRestart {
		t.Fatal("new PowerDNS TSIG state did not request a restart")
	}
	if len(runner.values) != 1 || !strings.Contains(runner.values[0], secret) {
		t.Fatalf("PowerDNS secret did not use protected stdin: %#v", runner.values)
	}
	if strings.Contains(runner.commands[0], secret) {
		t.Fatal("PowerDNS secret entered the remote command")
	}
	if runner.users[0] != "root" || strings.Contains(runner.commands[0], "sudo") {
		t.Fatalf("PowerDNS exception did not use the temporary root transport: users=%v commands=%v", runner.users, runner.commands)
	}
}

func TestPowerDNSTSIGChangeMarkerControlsRestart(t *testing.T) {
	for _, test := range []struct {
		name        string
		output      string
		wantRestart bool
	}{
		{name: "changed", output: "1\n", wantRestart: true},
		{name: "unchanged", output: "0\n", wantRestart: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := parsePowerDNSTSIGChange([]byte(test.output))
			if err != nil {
				t.Fatal(err)
			}
			if got != test.wantRestart {
				t.Fatalf("restart decision = %v, want %v", got, test.wantRestart)
			}
		})
	}
}

func TestPowerDNSTSIGSyncMarkerState(t *testing.T) {
	for _, test := range []struct {
		name    string
		output  string
		missing bool
	}{
		{name: "present", output: "present\n", missing: false},
		{name: "absent", output: "absent\n", missing: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &credentialDeploymentRunner{runOutput: []byte(test.output)}
			got, err := powerDNSTSIGSyncMarkerMissing(context.Background(), runner, "10.10.10.10")
			if err != nil {
				t.Fatal(err)
			}
			if got != test.missing {
				t.Fatalf("marker missing = %v, want %v", got, test.missing)
			}
			if len(runner.commands) != 1 || !strings.Contains(runner.commands[0], powerDNSTSIGSyncMarker) {
				t.Fatalf("marker check command = %v", runner.commands)
			}
		})
	}
}

func TestPulseProxyAuthUsesSeparateEncryptedUnitCredentials(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := deploymentCredentialBindings(site)
	if err != nil {
		t.Fatal(err)
	}
	dropIns, err := credentialDropIns(bindings)
	if err != nil {
		t.Fatal(err)
	}
	pulse := dropIns["lab-monitor-01"]["pulse.service"]
	nginx := dropIns["lab-monitor-01"]["nginx.service"]
	for _, expected := range []string{
		"LoadCredentialEncrypted=pulse-proxy-auth-secret:/var/lib/boetticher/credentials/pulse-proxy-auth-secret.cred",
	} {
		if !strings.Contains(pulse, expected) {
			t.Fatalf("Pulse proxy-auth credential projection is missing %q: %s", expected, pulse)
		}
	}
	if !strings.Contains(nginx, "LoadCredentialEncrypted=pulse-proxy-auth-nginx-secret:/var/lib/boetticher/credentials/pulse-proxy-auth-nginx-secret.cred") || strings.Contains(pulse+nginx, "synthetic-secret") {
		t.Fatalf("nginx proxy-auth credential projection is incomplete or leaked a value: pulse=%s nginx=%s", pulse, nginx)
	}
}
