package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/gofastercloud/boetticher/internal/ansible"
	"github.com/gofastercloud/boetticher/internal/dns"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/secrets"
)

// deploymentCredential binds a controller-side recovery secret to one
// consuming appliance unit. The secret value is deliberately kept outside
// this metadata and outside the Ansible variable document.
type deploymentCredential struct {
	Guest     string
	Address   string
	SecretKey string
	Spec      secrets.CredentialSpec
}

func deploymentCredentialBindings(site model.Site) ([]deploymentCredential, error) {
	bindings := make([]deploymentCredential, 0, 4)
	if site.Gateway.Mode == model.GatewayModeManaged {
		bindings = append(bindings, deploymentCredential{
			Guest:     "lab-fw-01",
			Address:   "10.10.99.1",
			SecretKey: "firewall-ddns-tsig",
			Spec: secrets.CredentialSpec{
				Name:       "kea-ddns-tsig",
				Unit:       "kea-dhcp-ddns-server.service",
				StorePath:  "/var/lib/boetticher/credentials/kea-ddns-tsig.cred",
				RuntimeRef: "/run/credentials/kea-dhcp-ddns-server.service/kea-ddns-tsig",
			},
		})
	}
	if modules.IsEnabled(site, "monitoring") {
		bindings = append(bindings, deploymentCredential{
			Guest:     "lab-monitor-01",
			Address:   "10.10.10.20",
			SecretKey: "pulse_admin_password",
			Spec: secrets.CredentialSpec{
				Name:       "pulse-admin-password",
				Unit:       "pulse.service",
				StorePath:  "/var/lib/boetticher/credentials/pulse-admin-password.cred",
				RuntimeRef: "/run/credentials/pulse.service/pulse-admin-password",
			},
		})
	}
	if modules.IsEnabled(site, "tailnet-router") {
		bindings = append(bindings, deploymentCredential{
			Guest: "lab-tailnet-01", Address: "10.10.5.10", SecretKey: "tailscale_auth_key",
			Spec: secrets.CredentialSpec{Name: "tailscale-auth-key", Unit: "tailscaled.service", StorePath: "/var/lib/boetticher/credentials/tailscale-auth-key.cred", RuntimeRef: "/run/credentials/tailscaled.service/tailscale-auth-key"},
		})
	}
	if modules.IsEnabled(site, "litellm") {
		for _, upstream := range site.ModuleConfig["litellm"].Upstreams {
			bindings = append(bindings, deploymentCredential{
				Guest: "lab-litellm-01", Address: "10.10.20.60", SecretKey: upstream.APIKeySecret,
				Spec: secrets.CredentialSpec{Name: credentialName(upstream.APIKeySecret), Unit: "litellm.service", StorePath: "/var/lib/boetticher/credentials/" + credentialName(upstream.APIKeySecret) + ".cred", RuntimeRef: "/run/credentials/litellm.service/" + credentialName(upstream.APIKeySecret)},
			})
		}
	}
	if modules.IsEnabled(site, "aiops") {
		for _, binding := range []struct{ key, name string }{
			{key: "aiops_webhook_secret", name: "webhook-secret"},
			{key: "aiops_pulse_read_token", name: "pulse-read-token"},
			{key: "aiops_pulse_note_token", name: "pulse-note-token"},
		} {
			bindings = append(bindings, deploymentCredential{Guest: "lab-aiops-01", Address: "10.10.20.90", SecretKey: binding.key, Spec: secrets.CredentialSpec{Name: binding.name, Unit: "boetticher-aiops.service", StorePath: "/var/lib/boetticher/credentials/aiops-" + binding.name + ".cred", RuntimeRef: "/run/credentials/boetticher-aiops.service/" + binding.name}})
		}
	}
	items := make([]secrets.CredentialSpec, 0, len(bindings))
	for _, binding := range bindings {
		items = append(items, binding.Spec)
	}
	if err := secrets.Validate(items); err != nil {
		return nil, fmt.Errorf("validate appliance credential declarations: %w", err)
	}
	return bindings, nil
}

// monitoringAgentCredentialBindings creates one systemd credential projection
// for each model component carrying the generic monitoring-agent tag. The
// token is created only after Pulse is configured, so these bindings are
// deliberately installed in the post-bootstrap pass rather than mixed into
// the initial credential load.
func monitoringAgentCredentialBindings(site model.Site) ([]deploymentCredential, error) {
	if !modules.IsEnabled(site, "monitoring") {
		return nil, nil
	}
	components := make(map[string]model.Component)
	for _, component := range site.PlatformComponents() {
		components[component.Name] = component
	}
	bindings := make([]deploymentCredential, 0)
	for _, target := range ansible.MonitoringAgentTargets(site) {
		component, ok := components[target]
		if !ok || !component.SSHManaged {
			return nil, fmt.Errorf("monitoring-agent target %q is not a managed platform component", target)
		}
		address := component.Address
		if target == model.LogicalProxmoxIdentity && site.BootstrapAddress != "" {
			address = site.BootstrapAddress
		}
		if address == "" {
			return nil, fmt.Errorf("monitoring-agent target %q has no deployment address", target)
		}
		bindings = append(bindings, deploymentCredential{
			Guest: target, Address: address, SecretKey: "pulse_agent_token",
			Spec: secrets.CredentialSpec{
				Name:       "pulse-agent-token",
				Unit:       "pulse-agent.service",
				StorePath:  "/var/lib/boetticher/credentials/pulse-agent-token.cred",
				RuntimeRef: "/run/credentials/pulse-agent.service/pulse-agent-token",
			},
		})
	}
	items := make([]secrets.CredentialSpec, 0, len(bindings))
	for _, binding := range bindings {
		items = append(items, binding.Spec)
	}
	if err := secrets.Validate(items); err != nil {
		return nil, fmt.Errorf("validate monitoring-agent credential declarations: %w", err)
	}
	return bindings, nil
}

// streamDeckCredentialBindings creates the single runtime projection needed
// by the read-only StreamDeck client. Pulse owns the token; Core installs it
// only after the mTLS Pulse read path has passed its deployment gate.
func streamDeckCredentialBindings(site model.Site) ([]deploymentCredential, error) {
	if !modules.IsEnabled(site, "streamdeck") {
		return nil, nil
	}
	binding := deploymentCredential{
		Guest: "lab-streamdeck-01", Address: "10.10.20.70", SecretKey: "pulse_api_token",
		Spec: secrets.CredentialSpec{
			Name:       "pulse-token",
			Unit:       "streamdeck-status.service",
			StorePath:  "/var/lib/boetticher/credentials/streamdeck-pulse-token.cred",
			RuntimeRef: "/run/credentials/streamdeck-status.service/pulse-token",
		},
	}
	if err := secrets.Validate([]secrets.CredentialSpec{binding.Spec}); err != nil {
		return nil, fmt.Errorf("validate StreamDeck credential declaration: %w", err)
	}
	return []deploymentCredential{binding}, nil
}

func credentialName(reference string) string {
	return model.LiteLLMSecretReferenceID(reference)
}

// credentialDropIns returns non-secret systemd projections grouped by
// appliance. Store paths identify encrypted files; no decrypted value enters
// the result.
func credentialDropIns(bindings []deploymentCredential) (map[string]map[string]string, error) {
	byGuest := make(map[string][]secrets.CredentialSpec)
	for _, binding := range bindings {
		byGuest[binding.Guest] = append(byGuest[binding.Guest], binding.Spec)
	}
	result := make(map[string]map[string]string, len(byGuest))
	for guest, specs := range byGuest {
		dropIns, err := secrets.UnitDropIns(specs)
		if err != nil {
			return nil, fmt.Errorf("render credential drop-ins for %s: %w", guest, err)
		}
		result[guest] = dropIns
	}
	return result, nil
}

func installCredentialsForGuest(ctx context.Context, runner proxmox.CommandRunner, guest string, bindings []deploymentCredential, values map[string]string) error {
	var selected []deploymentCredential
	for _, binding := range bindings {
		if binding.Guest == guest {
			selected = append(selected, binding)
		}
	}
	if len(selected) == 0 {
		return nil
	}
	if runner == nil {
		return fmt.Errorf("credential runner is required for %s", guest)
	}
	if _, err := runner.Run(ctx, selected[0].Address, "root", "install -d -m 0700 -o root -g root /var/lib/boetticher/credentials"); err != nil {
		return fmt.Errorf("prepare encrypted credential store on %s: %w", guest, err)
	}
	stdinRunner, ok := runner.(secrets.StdinRunner)
	if !ok {
		return fmt.Errorf("credential runner for %s cannot stream protected values", guest)
	}
	for _, binding := range selected {
		value := values[binding.SecretKey]
		if value == "" {
			return fmt.Errorf("secret value for %s is unavailable", binding.Spec.Name)
		}
		if err := secrets.InstallCredential(ctx, stdinRunner, binding.Address, "root", binding.Spec, []byte(value)); err != nil {
			return fmt.Errorf("install %s credential on %s: %w", binding.Spec.Name, guest, err)
		}
	}
	if _, err := runner.Run(ctx, selected[0].Address, "root", "systemctl daemon-reload"); err != nil {
		return fmt.Errorf("reload systemd after credential installation on %s: %w", guest, err)
	}
	return nil
}

// installPowerDNSTSIG is the explicit protected-backend exception for
// PowerDNS. The supported SQLite backend persists TSIG material, so Core
// streams one bounded SQL document over SSH after the database exists.
func installPowerDNSTSIG(ctx context.Context, runner proxmox.StdinCommandRunner, address string, plan dns.Plan, secret string) error {
	if runner == nil || secret == "" {
		return fmt.Errorf("PowerDNS TSIG installation requires a runner and secret")
	}
	var sql strings.Builder
	sql.WriteString("BEGIN;\n")
	for _, zone := range plan.DDNS.Zones {
		fmt.Fprintf(&sql, "INSERT OR REPLACE INTO tsigkeys (name, algorithm, secret) VALUES (%s, %s, %s);\n", sqlQuote(zone.TSIGKeyName), sqlQuote(plan.DDNS.TSIGAlgorithm), sqlQuote(secret))
	}
	sql.WriteString("COMMIT;\n")
	if _, err := runner.RunWithStdin(ctx, address, "root", "sqlite3 /var/lib/powerdns/pdns.sqlite3", strings.NewReader(sql.String())); err != nil {
		return fmt.Errorf("install PowerDNS protected TSIG backend state: %w", err)
	}
	return nil
}

func sqlQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
