package cli

import (
	"context"
	"fmt"
	"strings"

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
			SecretKey: "monitoring-db-password",
			Spec: secrets.CredentialSpec{
				Name:       "zabbix-db-password",
				Unit:       "zabbix-server.service",
				StorePath:  "/var/lib/boetticher/credentials/zabbix-db-password.cred",
				RuntimeRef: "/run/credentials/zabbix-server.service/zabbix-db-password",
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
	items := make([]secrets.CredentialSpec, 0, len(bindings))
	for _, binding := range bindings {
		items = append(items, binding.Spec)
	}
	if err := secrets.Validate(items); err != nil {
		return nil, fmt.Errorf("validate appliance credential declarations: %w", err)
	}
	return bindings, nil
}

func credentialName(reference string) string {
	var b strings.Builder
	for _, character := range strings.ToLower(reference) {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			b.WriteRune(character)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
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

// installZabbixAPIPassword updates the controller login after the database
// exists. It is a Core provider operation and does not pass the value through
// Ansible variables or command arguments.
func installZabbixAPIPassword(ctx context.Context, runner proxmox.StdinCommandRunner, address, secret string) error {
	if runner == nil || secret == "" {
		return fmt.Errorf("Zabbix API password installation requires a runner and secret")
	}
	sql := "CREATE EXTENSION IF NOT EXISTS pgcrypto;\nUPDATE users SET passwd = crypt(" + sqlQuote(secret) + ", gen_salt('bf')) WHERE username = 'Admin';\n"
	if _, err := runner.RunWithStdin(ctx, address, "root", "runuser -u postgres -- psql --dbname zabbix --set ON_ERROR_STOP=1", strings.NewReader(sql)); err != nil {
		return fmt.Errorf("install Zabbix API password: %w", err)
	}
	return nil
}

func sqlQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
