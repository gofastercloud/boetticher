package zabbix

import "github.com/gofastercloud/boetticher/internal/model"

const PlatformHostGroup = "boetticher/platform"

type Plan struct {
	ModelRevision string            `json:"model_revision"`
	Target        string            `json:"target"`
	ManagedBy     string            `json:"managed_by"`
	HostGroup     string            `json:"host_group"`
	PlatformOnly  bool              `json:"platform_only"`
	Components    []model.Component `json:"components"`
	Objects       []ManagedObject   `json:"objects"`
}

// ManagedObject is a deterministic, namespaced Zabbix object definition.
// Reconciliation is limited to objects carrying the boetticher/platform tag.
type ManagedObject struct {
	Kind        string   `json:"kind"`
	Name        string   `json:"name"`
	Key         string   `json:"key,omitempty"`
	ManagedBy   string   `json:"managed_by"`
	Tags        []string `json:"tags"`
	Description string   `json:"description"`
}

func PlanFromSite(s model.Site) (Plan, error) {
	if err := s.Validate(); err != nil {
		return Plan{}, err
	}
	revision, err := s.Revision()
	if err != nil {
		return Plan{}, err
	}
	return Plan{
		ModelRevision: revision,
		Target:        model.ZabbixSeries,
		ManagedBy:     "boetticher",
		HostGroup:     PlatformHostGroup,
		PlatformOnly:  true,
		Components:    s.PlatformComponents(),
		Objects:       platformObjects(),
	}, nil
}

func platformObjects() []ManagedObject {
	tag := []string{"boetticher/platform"}
	return []ManagedObject{
		{Kind: "template", Name: "boetticher Linux platform", Key: "boetticher.linux", ManagedBy: "boetticher", Tags: append([]string(nil), tag...), Description: "CPU, memory, filesystem, service, NTP, and certificate checks for managed Linux hosts"},
		{Kind: "template", Name: "boetticher Proxmox platform", Key: "boetticher.proxmox", ManagedBy: "boetticher", Tags: append([]string(nil), tag...), Description: "Read-only Proxmox API health, storage, guest, and backup checks"},
		{Kind: "template", Name: "boetticher OPNsense platform", Key: "boetticher.opnsense", ManagedBy: "boetticher", Tags: append([]string(nil), tag...), Description: "Read-only OPNsense health and network-boundary checks"},
		{Kind: "dashboard", Name: "boetticher Platform Overview", ManagedBy: "boetticher", Tags: append([]string(nil), tag...), Description: "Platform, firewall, DNS, NTP, storage, certificates, backups, and service health"},
		{Kind: "dashboard", Name: "boetticher Network and Security", ManagedBy: "boetticher", Tags: append([]string(nil), tag...), Description: "Firewall policy and service reachability overview"},
		{Kind: "dashboard", Name: "boetticher Recovery", ManagedBy: "boetticher", Tags: append([]string(nil), tag...), Description: "Backup freshness, certificate expiry, and recovery metadata"},
		{Kind: "check", Name: "boetticher portal HTTPS", Key: "net.tcp.service[https,portal.lab.home.arpa,443]", ManagedBy: "boetticher", Tags: append([]string(nil), tag...), Description: "Portal TLS and availability check"},
		{Kind: "check", Name: "boetticher Zabbix HTTPS", Key: "net.tcp.service[https,monitor.lab.home.arpa,443]", ManagedBy: "boetticher", Tags: append([]string(nil), tag...), Description: "Zabbix frontend TLS and availability check"},
		{Kind: "check", Name: "boetticher DNS01 authoritative", Key: "net.tcp.service[tcp,10.10.20.10,5353]", ManagedBy: "boetticher", Tags: append([]string(nil), tag...), Description: "PowerDNS authoritative listener check"},
		{Kind: "check", Name: "boetticher DNS02 authoritative", Key: "net.tcp.service[tcp,10.10.20.11,5353]", ManagedBy: "boetticher", Tags: append([]string(nil), tag...), Description: "PowerDNS secondary listener check"},
	}
}
