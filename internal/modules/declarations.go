package modules

import (
	"fmt"
	"sort"

	"github.com/gofastercloud/boetticher/internal/artifacts"
	"github.com/gofastercloud/boetticher/internal/logging"
	"github.com/gofastercloud/boetticher/internal/model"
)

const tailscaleDERPRegionCount = 28

func composeDeclarations(site model.Site, resolved []ResolvedModule) ([]model.ModuleDeclaration, error) {
	declarations := make([]model.ModuleDeclaration, 0, len(resolved))
	for _, module := range resolved {
		if !module.Enabled {
			continue
		}
		declaration, err := declarationFor(module.Definition, site)
		if err != nil {
			return nil, err
		}
		declarations = append(declarations, declaration)
	}
	sort.Slice(declarations, func(i, j int) bool { return declarations[i].Module < declarations[j].Module })
	return declarations, nil
}

func declarationFor(definition ModuleDefinition, site model.Site) (model.ModuleDeclaration, error) {
	name := definition.Name
	components, err := moduleGuestProjections(definition, site)
	if err != nil {
		return model.ModuleDeclaration{}, err
	}
	artifact, err := artifacts.ArtifactFor(name)
	if err != nil {
		return model.ModuleDeclaration{}, err
	}
	declaration := model.ModuleDeclaration{Module: name, Artifact: artifact}
	declaration.USBRequirements = append([]model.USBRequirement(nil), definition.USBRequirements...)
	for _, component := range components {
		declaration.Guests = append(declaration.Guests, component)
		declaration.Backups = append(declaration.Backups, model.BackupDeclaration{Guest: component.Name, Policy: "platform-default"})
		declaration.Monitoring = append(declaration.Monitoring, model.MonitoringDeclaration{Name: component.Name, Kind: "host", Target: component.Hostname, Checks: []string{"cpu", "memory", "filesystem", "service"}, Description: name + " module appliance health"})
		declaration.Certificates = append(declaration.Certificates, model.CertificateRequest{Identity: component.Hostname, SANs: []string{component.Hostname + "." + site.Network.Domain}, Consumer: component.Name})
		declaration.Persistent = append(declaration.Persistent, persistentFor(name, component.Name)...)
		declaration.Volumes = append(declaration.Volumes, volumesFor(name, component.Name)...)
	}
	switch name {
	case "dns":
		declaration.Secrets = []model.SecretDeclaration{
			{Name: "ddns_tsig_secret", Purpose: "authenticated DHCP DNS updates", Consumer: "kea-dhcp-ddns-server", Generation: "random", Rotation: "replaceable", Delivery: "systemd-credential-to-ephemeral-secret-file", Lifecycle: model.SecretLifecycleRuntime},
			{Name: "ddns_tsig_secret", Purpose: "PowerDNS authenticated update authorization", Consumer: "powerdns-authoritative", Generation: "random", Rotation: "replaceable", Delivery: "protected-powerdns-backend", Lifecycle: model.SecretLifecycleRuntime, Persistent: true},
		}
		declaration.DNSRecords = []model.DNSRecord{{Name: "dns01." + site.Network.Domain, Type: "A", Address: "10.10.10.10", Owner: "dns"}, {Name: "dns02." + site.Network.Domain, Type: "A", Address: "10.10.10.11", Owner: "dns"}}
	case "monitoring":
		declaration.Secrets = []model.SecretDeclaration{
			{Name: "pulse_admin_password", Purpose: "Pulse administrative bootstrap authentication", Consumer: "pulse-server", Generation: "random", Rotation: "replaceable", Delivery: "systemd-credential", Lifecycle: model.SecretLifecycleRuntime},
			{Name: "pulse_proxmox_token", Purpose: "API-only Proxmox monitoring token value", Consumer: "deployment-controller", Generation: "ephemeral", Rotation: "replaceable", Delivery: "controller-memory", Lifecycle: model.SecretLifecycleRuntime},
			{Name: "pulse_api_token", Purpose: "read-only Pulse monitoring API integration", Consumer: "deployment-controller", Generation: "ephemeral", Rotation: "replaceable", Delivery: "controller-memory", Lifecycle: model.SecretLifecycleRuntime},
			{Name: "pulse_agent_token", Purpose: "read-only Pulse host-agent report authentication", Consumer: "pulse-agent", Generation: "ephemeral", Rotation: "replaceable", Delivery: "systemd-credential", Lifecycle: model.SecretLifecycleRuntime},
		}
		declaration.NetworkIntents = []model.NetworkIntent{{Source: "lab-monitor-01", Destination: model.LogicalProxmoxIdentity, Protocol: "tcp", Ports: []string{"8006"}, Direction: "egress", Purpose: "Proxmox API monitoring"}}
	case "firewall":
		declaration.Secrets = []model.SecretDeclaration{{Name: "ddns_tsig_secret", Purpose: "authenticated DHCP DNS updates", Consumer: "kea-dhcp-ddns-server", Generation: "random", Rotation: "replaceable", Delivery: "systemd-credential-to-ephemeral-secret-file", Lifecycle: model.SecretLifecycleRuntime}}
	case "logging":
		declaration.NetworkIntents = []model.NetworkIntent{
			{Source: "boetticher-managed-endpoints", Destination: "logs." + site.Network.Domain, Protocol: "tcp", Ports: []string{"19532"}, Direction: "egress", Purpose: "native journal upload"},
			{Source: model.LogicalProxmoxIdentity, Destination: "logs." + site.Network.Domain, Protocol: "tcp", Ports: []string{"19532"}, Direction: "egress", Purpose: "native Proxmox journal upload"},
		}
		declaration.Certificates = append(declaration.Certificates, model.CertificateRequest{Identity: "logs." + site.Network.Domain, SANs: []string{"logs." + site.Network.Domain}, Consumer: "systemd-journal-remote"})
		if IsEnabled(site, "aiops") {
			declaration.Certificates = append(declaration.Certificates, model.CertificateRequest{Identity: "log-query." + site.Network.Domain, SANs: []string{"logs." + site.Network.Domain, "lab-log-01." + site.Network.Domain}, Consumer: "boetticher-log-query"})
		}
		declaration.Portal = []model.PortalEntry{{Name: "logging", Description: "Central systemd journal collection", Docs: []string{"docs/operations/logs.md"}}}
	case "tailnet-router":
		declaration.Secrets = []model.SecretDeclaration{{Name: "tailscale_auth_key", Purpose: "initial Tailscale registration or re-registration", Consumer: "tailscaled", Generation: "operator-supplied", Rotation: "replaceable", Delivery: "systemd-credential-to-ephemeral-secret-file", Lifecycle: model.SecretLifecycleBootstrap}}
		declaration.AdvertisedRoutes = []string{"10.10.0.0/16"}
		declaration.ReturnRouting = []string{"Tailnet return traffic for 10.10.0.0/16 must use the TRANSIT gateway 10.10.5.1"}
		declaration.Security = model.GuestSecurityDeclaration{Unprivileged: true, Devices: []model.DeviceRequirement{{Name: "tun", Path: "/dev/net/tun", Type: "c", Major: 10, Minor: 200, Access: "rwm"}}}
		declaration.NetworkIntents = []model.NetworkIntent{
			{Source: "lab-tailnet-01", Destination: "litellm", Protocol: "tcp", Ports: []string{"443"}, Direction: "egress", Purpose: "routed LiteLLM HTTPS access"},
			{Source: "lab-tailnet-01", Destination: "portal", Protocol: "tcp", Ports: []string{"443"}, Direction: "egress", Purpose: "routed portal HTTPS access"},
			{Source: "lab-tailnet-01", Destination: "monitor", Protocol: "tcp", Ports: []string{"443"}, Direction: "egress", Purpose: "routed monitoring HTTPS access"},
			{Source: "lab-tailnet-01", Destination: "dns", Protocol: "tcp/udp", Ports: []string{"53"}, Direction: "egress", Purpose: "Tailscale router DNS resolution"},
			{Source: "lab-tailnet-01", Destination: "dns", Protocol: "udp", Ports: []string{"123"}, Direction: "egress", Purpose: "Tailscale router time synchronisation"},
			{Source: "lab-tailnet-01", Destination: "tailscale-control-plane", Endpoint: "https://controlplane.tailscale.com", Protocol: "tcp", Ports: []string{"443"}, Direction: "egress", Purpose: "Tailscale control-plane operation"},
		}
		for region := 1; region <= tailscaleDERPRegionCount; region++ {
			host := fmt.Sprintf("derp%d-all.tailscale.com", region)
			declaration.NetworkIntents = append(declaration.NetworkIntents, model.NetworkIntent{Source: "lab-tailnet-01", Destination: fmt.Sprintf("tailscale-derp-%02d", region), Endpoint: "https://" + host, Protocol: "tcp", Ports: []string{"443"}, Direction: "egress", Purpose: "Tailscale DERP region operation"})
		}
		if IsEnabled(site, "logging") {
			declaration.NetworkIntents = append(declaration.NetworkIntents, model.NetworkIntent{Source: "lab-tailnet-01", Destination: "logs." + site.Network.Domain, Protocol: "tcp", Ports: []string{"19532"}, Direction: "egress", Purpose: "native journal upload"})
		}
		declaration.Monitoring = append(declaration.Monitoring, model.MonitoringDeclaration{Name: "tailscaled", Kind: "service", Target: "lab-tailnet-01", Checks: []string{"tailscaled", "route-advertisement"}, Description: "Tailscale daemon and advertised subnet route health"})
		declaration.Portal = []model.PortalEntry{{Name: "tailnet-router", Description: "Tailscale subnet router; Internet exit-node behavior is not enabled", Docs: []string{"docs/modules/tailnet-router.md"}}}
	case "litellm":
		config := site.ModuleConfig[name]
		for _, upstream := range config.Upstreams {
			declaration.Secrets = appendUniqueSecret(declaration.Secrets, model.SecretDeclaration{Name: upstream.APIKeySecret, Purpose: "server-side credential for the configured LiteLLM upstream", Consumer: "litellm", Generation: "operator-supplied", Rotation: "replaceable", Delivery: "systemd-credential-to-ephemeral-secret-file", Lifecycle: model.SecretLifecycleRuntime})
			declaration.NetworkIntents = append(declaration.NetworkIntents, model.NetworkIntent{Source: "lab-litellm-01", Destination: upstream.Name, Endpoint: upstream.BaseURL, Protocol: "tcp", Ports: []string{"443"}, Direction: "egress", Purpose: "configured LiteLLM upstream HTTPS access"})
		}
		declaration.NetworkIntents = append(declaration.NetworkIntents,
			model.NetworkIntent{Source: "lab-litellm-01", Destination: "dns", Protocol: "tcp/udp", Ports: []string{"53"}, Direction: "egress", Purpose: "LiteLLM DNS resolution"},
			model.NetworkIntent{Source: "lab-litellm-01", Destination: "dns", Protocol: "udp", Ports: []string{"123"}, Direction: "egress", Purpose: "LiteLLM time synchronisation"},
		)
		if IsEnabled(site, "logging") {
			declaration.NetworkIntents = append(declaration.NetworkIntents, model.NetworkIntent{Source: "lab-litellm-01", Destination: "logs." + site.Network.Domain, Protocol: "tcp", Ports: []string{"19532"}, Direction: "egress", Purpose: "native journal upload"})
		}
		declaration.Certificates = append(declaration.Certificates, model.CertificateRequest{Identity: "litellm." + site.Network.Domain, SANs: []string{"litellm." + site.Network.Domain, "ai." + site.Network.Domain}, Consumer: "nginx"})
		declaration.Monitoring = append(declaration.Monitoring,
			model.MonitoringDeclaration{Name: "nginx", Kind: "service", Target: "lab-litellm-01", Checks: []string{"nginx", "https", "mtls"}, Description: "LiteLLM mTLS frontend health"},
			model.MonitoringDeclaration{Name: "litellm", Kind: "service", Target: "lab-litellm-01", Checks: []string{"litellm", "loopback"}, Description: "LiteLLM loopback backend health"},
		)
		declaration.Portal = []model.PortalEntry{{Name: "litellm", Description: "mTLS-protected provider-neutral AI API aliases", URLs: []string{"https://litellm." + site.Network.Domain}, Docs: []string{"docs/modules/litellm.md"}}}
	case "printer":
		declaration.Security = model.GuestSecurityDeclaration{Unprivileged: true}
		declaration.DNSRecords = []model.DNSRecord{{Name: "octoprint." + site.Network.Domain, Type: "A", Address: "10.10.20.80", Owner: "printer"}, {Name: "printer." + site.Network.Domain, Type: "A", Address: "10.10.20.80", Owner: "printer"}}
		declaration.NetworkIntents = []model.NetworkIntent{
			{Source: "lab-printer-01", Destination: "dns", Protocol: "tcp/udp", Ports: []string{"53"}, Direction: "egress", Purpose: "OctoPrint DNS resolution"},
			{Source: "lab-printer-01", Destination: "dns", Protocol: "udp", Ports: []string{"123"}, Direction: "egress", Purpose: "OctoPrint time synchronisation"},
		}
		if IsEnabled(site, "logging") {
			declaration.NetworkIntents = append(declaration.NetworkIntents, model.NetworkIntent{Source: "lab-printer-01", Destination: "logs." + site.Network.Domain, Protocol: "tcp", Ports: []string{"19532"}, Direction: "egress", Purpose: "native journal upload"})
		}
		declaration.Certificates = append(declaration.Certificates, model.CertificateRequest{Identity: "octoprint." + site.Network.Domain, SANs: []string{"octoprint." + site.Network.Domain, "printer." + site.Network.Domain}, Consumer: "nginx"})
		declaration.Monitoring = append(declaration.Monitoring,
			model.MonitoringDeclaration{Name: "nginx", Kind: "service", Target: "lab-printer-01", Checks: []string{"nginx", "https", "mtls"}, Description: "OctoPrint mTLS frontend health"},
			model.MonitoringDeclaration{Name: "octoprint", Kind: "service", Target: "lab-printer-01", Checks: []string{"octoprint", "loopback", "serial"}, Description: "OctoPrint backend and printer serial availability"},
		)
		declaration.Portal = []model.PortalEntry{{Name: "printer", Description: "mTLS-protected OctoPrint management for the Ender-3 V3 SE", URLs: []string{"https://octoprint." + site.Network.Domain}, Docs: []string{"docs/modules/printer.md"}}}
	case "streamdeck":
		declaration.Security = model.GuestSecurityDeclaration{Unprivileged: true}
		declaration.Secrets = []model.SecretDeclaration{{Name: "pulse_api_token", Purpose: "read-only Pulse monitoring API integration", Consumer: "streamdeck-status", Generation: "dependency", Rotation: "replaceable", Delivery: "systemd-credential", Lifecycle: model.SecretLifecycleRuntime}}
		declaration.Certificates = append(declaration.Certificates, model.CertificateRequest{Identity: "lab-streamdeck-01", SANs: []string{"lab-streamdeck-01." + site.Network.Domain}, Consumer: "streamdeck-status"})
		declaration.NetworkIntents = append(declaration.NetworkIntents,
			model.NetworkIntent{Source: "lab-streamdeck-01", Destination: "monitor." + site.Network.Domain, Protocol: "tcp", Ports: []string{"443"}, Direction: "egress", Purpose: "read-only Pulse Proxmox host status polling"},
			model.NetworkIntent{Source: "lab-streamdeck-01", Destination: "dns", Protocol: "tcp/udp", Ports: []string{"53"}, Direction: "egress", Purpose: "StreamDeck DNS resolution"},
			model.NetworkIntent{Source: "lab-streamdeck-01", Destination: "dns", Protocol: "udp", Ports: []string{"123"}, Direction: "egress", Purpose: "StreamDeck time synchronisation"},
		)
		declaration.Monitoring = append(declaration.Monitoring, model.MonitoringDeclaration{Name: "streamdeck-status", Kind: "service", Target: "lab-streamdeck-01", Checks: []string{"streamdeck-status", "usb"}, Description: "read-only Proxmox host status display and USB availability"})
	case "aiops":
		config := site.ModuleConfig[name]
		if _, err := model.ResolveLiteLLMAlias(site.ModuleConfig["litellm"], config.ModelAlias); err != nil {
			return model.ModuleDeclaration{}, fmt.Errorf("aiops model alias: %w", err)
		}
		declaration.Secrets = []model.SecretDeclaration{
			{Name: "aiops_webhook_secret", Purpose: "authenticate Pulse alert admission", Consumer: "boetticher-aiops", Generation: "random", Rotation: "replaceable", Delivery: "systemd-credential"},
			{Name: "aiops_pulse_read_token", Purpose: "read bounded Pulse evidence", Consumer: "boetticher-aiops", Generation: "ephemeral", Rotation: "replaceable", Delivery: "systemd-credential"},
			{Name: "aiops_pulse_note_token", Purpose: "write incident notes only", Consumer: "boetticher-aiops", Generation: "ephemeral", Rotation: "replaceable", Delivery: "systemd-credential"},
		}
		declaration.Certificates = append(declaration.Certificates,
			model.CertificateRequest{Identity: "aiops." + site.Network.Domain, SANs: []string{"aiops." + site.Network.Domain, "lab-aiops-01." + site.Network.Domain}, Consumer: "boetticher-aiops-server"},
			model.CertificateRequest{Identity: "aiops-pulse-read", SANs: []string{"aiops-pulse-read." + site.Network.Domain}, Consumer: "boetticher-aiops-pulse-read"},
			model.CertificateRequest{Identity: "aiops-pulse-note", SANs: []string{"aiops-pulse-note." + site.Network.Domain}, Consumer: "boetticher-aiops-pulse-note"},
			model.CertificateRequest{Identity: "aiops-log-read", SANs: []string{"aiops-log-read." + site.Network.Domain}, Consumer: "boetticher-aiops-log-read"},
			model.CertificateRequest{Identity: "aiops-router-client", SANs: []string{"aiops-router-client." + site.Network.Domain}, Consumer: "boetticher-aiops-router"},
		)
		declaration.NetworkIntents = []model.NetworkIntent{
			{Source: "lab-monitor-01", Destination: "lab-aiops-01", Protocol: "tcp", Ports: []string{"443"}, Direction: "egress", Purpose: "Pulse webhook delivery and AIOps health"},
			{Source: "lab-aiops-01", Destination: "monitor", Protocol: "tcp", Ports: []string{"443"}, Direction: "egress", Purpose: "bounded Pulse evidence reads and incident notes"},
			{Source: "lab-aiops-01", Destination: "logs." + site.Network.Domain, Protocol: "tcp", Ports: []string{"19533"}, Direction: "egress", Purpose: "bounded central journal evidence"},
			{Source: "lab-aiops-01", Destination: "litellm", Protocol: "tcp", Ports: []string{"443"}, Direction: "egress", Purpose: "selected AI Router model alias"},
			{Source: "lab-aiops-01", Destination: "dns", Protocol: "tcp/udp", Ports: []string{"53"}, Direction: "egress", Purpose: "AIOps DNS resolution"},
			{Source: "lab-aiops-01", Destination: "dns", Protocol: "udp", Ports: []string{"123"}, Direction: "egress", Purpose: "AIOps time synchronisation"},
			{Source: "lab-aiops-01", Destination: "logs." + site.Network.Domain, Protocol: "tcp", Ports: []string{"19532"}, Direction: "egress", Purpose: "native journal upload"},
		}
		declaration.Security = model.GuestSecurityDeclaration{Unprivileged: true}
		declaration.Monitoring = append(declaration.Monitoring,
			model.MonitoringDeclaration{Name: "boetticher-aiops", Kind: "service", Target: "lab-aiops-01", Checks: []string{"https", "queue", "budgets"}, Description: "durable incident adapter health"},
			model.MonitoringDeclaration{Name: "holmes", Kind: "service", Target: "lab-aiops-01", Checks: []string{"loopback"}, Description: "loopback-only HolmesGPT health"},
		)
		declaration.Portal = []model.PortalEntry{{Name: "aiops", Description: "Read-only HolmesGPT incident investigation", URLs: []string{"https://aiops." + site.Network.Domain}, Docs: []string{"docs/modules/aiops.md"}}}
	case "gatus":
		declaration.NetworkIntents = []model.NetworkIntent{{Source: "lab-gatus-01", Destination: "dns", Protocol: "tcp/udp", Ports: []string{"53"}, Direction: "egress", Purpose: "Gatus DNS resolution"}, {Source: "lab-gatus-01", Destination: "dns", Protocol: "udp", Ports: []string{"123"}, Direction: "egress", Purpose: "Gatus time synchronisation"}}
		declaration.Certificates = append(declaration.Certificates, model.CertificateRequest{Identity: "gatus." + site.Network.Domain, SANs: []string{"gatus." + site.Network.Domain, "lab-gatus-01." + site.Network.Domain}, Consumer: "nginx"})
		declaration.Portal = []model.PortalEntry{{Name: "gatus", Description: "Generated status page for declared services; user endpoints are not supported", URLs: []string{"https://gatus." + site.Network.Domain}, Docs: []string{"docs/modules/gatus.md"}}}
	default:
		return model.ModuleDeclaration{}, fmt.Errorf("no declaration implementation for first-party module %q", name)
	}
	return declaration, nil
}

func appendUniqueSecret(values []model.SecretDeclaration, secret model.SecretDeclaration) []model.SecretDeclaration {
	for _, existing := range values {
		if existing.Name == secret.Name {
			return values
		}
	}
	return append(values, secret)
}

func persistentFor(module, guest string) []model.PersistentState {
	identity := model.PersistentState{Name: "ssh-identity", Guest: guest, Path: "/var/lib/boetticher/identity/ssh", Kind: "endpoint-identity", Backup: true, Sensitive: true, Replacement: "retain-across-rootfs-replacement"}
	switch module {
	case "dns":
		return []model.PersistentState{identity, {Name: "powerdns-database", Guest: guest, Path: "/var/lib/powerdns", Kind: "application-database", Backup: true, Sensitive: true, Replacement: "retain-across-rootfs-replacement"}}
	case "monitoring":
		return []model.PersistentState{identity, {Name: "pulse-state", Guest: guest, Path: "/var/lib/pulse", Kind: "monitoring-state", Backup: true, Sensitive: true, Replacement: "retain-across-rootfs-replacement"}}
	case "firewall":
		return []model.PersistentState{
			identity,
			{Name: "kea-leases", Guest: guest, Path: "/var/lib/kea", Kind: "lease-state", Backup: true, Sensitive: false, Replacement: "retain-across-rootfs-replacement"},
			{Name: "firewall-telemetry", Guest: guest, Path: "/var/lib/boetticher/firewall-telemetry", Kind: "firewall-telemetry-database", Backup: true, Sensitive: false, Replacement: "retain-across-rootfs-replacement"},
		}
	case "tailnet-router":
		return []model.PersistentState{identity, {Name: "tailscale-state", Guest: guest, Path: "/var/lib/tailscale", Kind: "node-identity", Backup: true, Sensitive: true, Replacement: "retain-across-rootfs-replacement"}}
	case "litellm":
		return []model.PersistentState{identity, {Name: "tls-identity", Guest: guest, Path: "/var/lib/boetticher/identity/tls", Kind: "endpoint-tls", Backup: true, Sensitive: true, Replacement: "retain-across-rootfs-replacement"}}
	case "printer":
		return []model.PersistentState{identity,
			{Name: "octoprint-state", Guest: guest, Path: "/var/lib/octoprint", Kind: "application-state", Backup: true, Sensitive: true, Replacement: "retain-across-rootfs-replacement"},
			{Name: "tls-identity", Guest: guest, Path: "/var/lib/boetticher/identity/tls", Kind: "endpoint-tls", Backup: true, Sensitive: true, Replacement: "retain-across-rootfs-replacement"},
		}
	case "streamdeck":
		return []model.PersistentState{identity, {Name: "tls-identity", Guest: guest, Path: "/var/lib/boetticher/identity/tls", Kind: "endpoint-tls", Backup: true, Sensitive: true, Replacement: "retain-across-rootfs-replacement"}}
	case "aiops":
		return []model.PersistentState{identity, {Name: "aiops-state", Guest: guest, Path: "/var/lib/boetticher/aiops", Kind: "incident-state-and-endpoint-identities", Backup: true, Sensitive: true, Replacement: "retain-across-rootfs-replacement"}}
	default:
		return []model.PersistentState{identity}
	}
}

func volumesFor(module, guest string) []model.PersistentVolumeDeclaration {
	volume := func(name, mount string, size int, backup bool) model.PersistentVolumeDeclaration {
		return model.PersistentVolumeDeclaration{Name: name, Module: module, Guest: guest, SizeGiB: size, MountPath: mount, Placement: model.StorageDefault, Backup: backup}
	}
	identity := volume("ssh-identity", "/var/lib/boetticher/identity/ssh", 1, true)
	switch module {
	case "dns":
		return []model.PersistentVolumeDeclaration{identity, volume("powerdns-database", "/var/lib/powerdns", 8, true)}
	case "monitoring":
		return []model.PersistentVolumeDeclaration{identity, volume("pulse-state", "/var/lib/pulse", 8, true)}
	case "firewall":
		return []model.PersistentVolumeDeclaration{identity, volume("kea-leases", "/var/lib/kea", 4, true), volume("firewall-telemetry", "/var/lib/boetticher/firewall-telemetry", 2, true)}
	case "tailnet-router":
		return []model.PersistentVolumeDeclaration{identity, volume("tailscale-state", "/var/lib/tailscale", 4, true)}
	case "litellm":
		return []model.PersistentVolumeDeclaration{identity, volume("tls-identity", "/var/lib/boetticher/identity/tls", 1, true)}
	case "printer":
		return []model.PersistentVolumeDeclaration{identity, volume("octoprint-state", "/var/lib/octoprint", 8, true), volume("tls-identity", "/var/lib/boetticher/identity/tls", 1, true)}
	case "streamdeck":
		return []model.PersistentVolumeDeclaration{identity, volume("tls-identity", "/var/lib/boetticher/identity/tls", 1, true)}
	case "aiops":
		return []model.PersistentVolumeDeclaration{identity, volume("aiops-state", "/var/lib/boetticher/aiops", 1, true)}
	case "logging":
		// Central journals are a bounded secondary evidence cache. The logging
		// appliance remains in the platform backup set, while this high-churn
		// volume is intentionally excluded from guest backups.
		v := volume("journal", "/var/log/journal/remote", logging.CollectorVolumeGiB, false)
		v.Placement = model.StoragePreferDataDisk
		return []model.PersistentVolumeDeclaration{identity, v}
	default:
		return []model.PersistentVolumeDeclaration{identity}
	}
}
