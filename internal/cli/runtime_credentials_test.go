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
	commands []string
	values   []string
}

func (r *credentialDeploymentRunner) Run(_ context.Context, _ string, _ string, command string) ([]byte, error) {
	r.commands = append(r.commands, command)
	return nil, nil
}

func (r *credentialDeploymentRunner) RunWithStdin(_ context.Context, _ string, _ string, command string, stdin io.Reader) ([]byte, error) {
	r.commands = append(r.commands, command)
	data, err := io.ReadAll(stdin)
	if err == nil {
		r.values = append(r.values, string(data))
	}
	return nil, err
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
	if strings.Contains(strings.Join([]string{dropIns["lab-fw-01"]["kea-dhcp-ddns-server.service"], dropIns["lab-monitor-01"]["zabbix-server.service"]}, "\n"), "synthetic-secret") {
		t.Fatal("credential projection contains a secret value")
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
	}
}

func TestPowerDNSExceptionStreamsProtectedBackendSQL(t *testing.T) {
	plan, err := dns.PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	runner := &credentialDeploymentRunner{}
	secret := "synthetic-powerdns-secret"
	if err := installPowerDNSTSIG(context.Background(), runner, "10.10.20.10", plan, secret); err != nil {
		t.Fatal(err)
	}
	if len(runner.values) != 1 || !strings.Contains(runner.values[0], secret) {
		t.Fatalf("PowerDNS secret did not use protected stdin: %#v", runner.values)
	}
	if strings.Contains(runner.commands[0], secret) {
		t.Fatal("PowerDNS secret entered the remote command")
	}
}
