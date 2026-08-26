package modules

import (
	"fmt"
	"sort"

	"github.com/gofastercloud/boetticher/internal/artifacts"
	"github.com/gofastercloud/boetticher/internal/model"
)

func composeDeclarations(site model.Site, resolved []ResolvedModule) ([]model.ModuleDeclaration, error) {
	declarations := make([]model.ModuleDeclaration, 0, len(resolved))
	for _, module := range resolved {
		if !module.Enabled {
			continue
		}
		declaration, err := declarationFor(module.Definition.Name, site)
		if err != nil {
			return nil, err
		}
		declarations = append(declarations, declaration)
	}
	sort.Slice(declarations, func(i, j int) bool { return declarations[i].Module < declarations[j].Module })
	return declarations, nil
}

func declarationFor(name string, site model.Site) (model.ModuleDeclaration, error) {
	components := moduleComponents(site, name)
	artifact, err := artifacts.ArtifactFor(name)
	if err != nil {
		return model.ModuleDeclaration{}, err
	}
	declaration := model.ModuleDeclaration{Module: name, Artifact: artifact}
	for _, component := range components {
		declaration.Guests = append(declaration.Guests, component)
		declaration.Backups = append(declaration.Backups, model.BackupDeclaration{Guest: component.Name, Policy: "platform-default"})
		declaration.Monitoring = append(declaration.Monitoring, model.MonitoringDeclaration{Name: component.Name, Kind: "host", Target: component.Hostname, Checks: []string{"cpu", "memory", "filesystem", "service"}, Description: name + " module appliance health"})
		declaration.Certificates = append(declaration.Certificates, model.CertificateRequest{Identity: component.Hostname, SANs: []string{component.Hostname + "." + site.Network.Domain}, Consumer: component.Name})
		declaration.Persistent = append(declaration.Persistent, persistentFor(name, component.Name)...)
	}
	switch name {
	case "dns":
		declaration.Secrets = []model.SecretDeclaration{
			{Name: "ddns_tsig_secret", Purpose: "authenticated DHCP DNS updates", Consumer: "kea-dhcp-ddns-server", Generation: "random", Rotation: "replaceable", Delivery: "systemd-credential-to-ephemeral-secret-file"},
			{Name: "ddns_tsig_secret", Purpose: "PowerDNS authenticated update authorization", Consumer: "powerdns-authoritative", Generation: "random", Rotation: "replaceable", Delivery: "protected-powerdns-backend", Persistent: true},
		}
		declaration.DNSRecords = []model.DNSRecord{{Name: "dns01." + site.Network.Domain, Type: "A", Address: "10.10.20.10", Owner: "dns"}, {Name: "dns02." + site.Network.Domain, Type: "A", Address: "10.10.20.11", Owner: "dns"}}
	case "monitoring":
		declaration.Secrets = []model.SecretDeclaration{
			{Name: "zabbix_db_password", Purpose: "monitoring database access", Consumer: "zabbix-server", Generation: "random", Rotation: "replaceable", Delivery: "systemd-credential"},
			{Name: "zabbix_api_password", Purpose: "bounded monitoring API reconciliation", Consumer: "controller", Generation: "random", Rotation: "replaceable", Delivery: "controller-memory"},
		}
	case "firewall":
		declaration.Secrets = []model.SecretDeclaration{{Name: "ddns_tsig_secret", Purpose: "authenticated DHCP DNS updates", Consumer: "kea-dhcp-ddns-server", Generation: "random", Rotation: "replaceable", Delivery: "systemd-credential-to-ephemeral-secret-file"}}
	default:
		return model.ModuleDeclaration{}, fmt.Errorf("no declaration provider for first-party module %q", name)
	}
	return declaration, nil
}

func moduleComponents(site model.Site, name string) []model.Component {
	components := make([]model.Component, 0)
	for _, component := range site.PlatformComponents() {
		if component.Module == name {
			components = append(components, component)
		}
	}
	sort.Slice(components, func(i, j int) bool { return components[i].Name < components[j].Name })
	return components
}

func persistentFor(module, guest string) []model.PersistentState {
	identity := model.PersistentState{Name: "ssh-identity", Guest: guest, Path: "/var/lib/boetticher/identity/ssh", Kind: "endpoint-identity", Backup: true, Sensitive: true, Replacement: "retain-across-rootfs-replacement"}
	switch module {
	case "dns":
		return []model.PersistentState{identity, {Name: "powerdns-database", Guest: guest, Path: "/var/lib/powerdns", Kind: "application-database", Backup: true, Sensitive: true, Replacement: "retain-across-rootfs-replacement"}}
	case "monitoring":
		return []model.PersistentState{identity, {Name: "postgresql-data", Guest: guest, Path: "/var/lib/postgresql", Kind: "application-database", Backup: true, Sensitive: true, Replacement: "retain-across-rootfs-replacement"}}
	case "firewall":
		return []model.PersistentState{identity, {Name: "kea-leases", Guest: guest, Path: "/var/lib/kea", Kind: "lease-state", Backup: true, Sensitive: false, Replacement: "retain-across-rootfs-replacement"}}
	default:
		return []model.PersistentState{identity}
	}
}
