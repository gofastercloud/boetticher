package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
)

const (
	APIVersion                  = "boetticher/v3"
	SchemaVersion               = 3
	PlatformVersion             = "0.3.18"
	QualifiedGatewayImage       = "debian-13-genericcloud-amd64-20260327-2429"
	QualifiedGatewayImageURL    = "https://cloud.debian.org/images/cloud/trixie/20260327-2429/debian-13-genericcloud-amd64-20260327-2429.qcow2"
	QualifiedGatewayImageSHA512 = "09559ec27d263997827dd8cddf76e97ea8e0f1803380aa501ea7eaa4b4968cd76ffef4ec7eb07ef1a9ccbeb0925a5020492ea9ed53eb167d62f3a2285039912c"
	ZabbixSeries                = "7.0 LTS"
	AuthoritativeDNS            = "PowerDNS Authoritative"
	AuthoritativeDNSVersion     = "4.9.17"
	AuthoritativePackageVersion = "4.9.17-1pdns.trixie"
	DefaultDomain               = "lab.home.arpa"
	DefaultSiteDir              = "my-boetticher"
	DefaultAgeIdentity          = "~/.config/boetticher/age/identity.txt"
	DefaultSSHConfig            = "~/.ssh/config.d/boetticher.conf"
	DefaultAdminSSHUser         = "labadmin"
	LogicalProxmoxIdentity      = "lab-proxmox-01"
	ProxmoxVMID                 = 100
	DNS01VMID                   = 110
	DNS02VMID                   = 111
	MonitorVMID                 = 120
	PortalVMID                  = 130
	LoggingVMID                 = 140
	BuilderVMID                 = 190
	BuilderCores                = 4
	BuilderMemoryMiB            = 8192
	BuilderDiskGiB              = 32
	BuilderMinimumFreeGiB       = 20
	BuilderMAC                  = "02:00:00:00:01:90"
	BuilderGoVersion            = "1.26.5"
	BuilderGoURL                = "https://go.dev/dl/go1.26.5.linux-amd64.tar.gz"
	BuilderGoSHA256             = "5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053"
	PlatformGuestIDMin          = 100
	PlatformGuestIDMax          = 199
	ModuleGuestIDMin            = 200
	ModuleGuestIDMax            = 499
	UserGuestIDMin              = 500
	UserGuestIDMax              = 899
	ModeVirtualOnly             = "virtual-only"
	ModePhysicalTrunk           = "physical-trunk"
	GatewayModeManaged          = "managed"
	GatewayModeExternal         = "external"
	TagBoetticher               = "boetticher"
	TagManaged                  = "managed"
	TagModule                   = "module"
	TagPlatform                 = "platform"
	TagInfra                    = "infra"
	TagBackup                   = "backup"
	TagNetwork                  = "network"
	TagFirewall                 = "firewall"
	TagGateway                  = "gateway"
	TagDNS                      = "dns"
	TagNTP                      = "ntp"
	TagObservability            = "observability"
	TagPortal                   = "portal"
	TagCorePortal               = "boetticher-core-portal"
)

var modelTokenPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,253}$`)

// ModuleOwnershipTag returns the single Proxmox-safe ownership proof used for
// every first-party module guest. Invalid names return an empty tag so callers
// fail closed instead of creating an ambiguous ownership representation.
func ModuleOwnershipTag(module string) string {
	if !modelTokenPattern.MatchString(module) {
		return ""
	}
	return "boetticher-module-" + module
}

type Site struct {
	APIVersion      string  `json:"api_version"`
	PlatformVersion string  `json:"platform_version"`
	SchemaVersion   int     `json:"schema_version"`
	StorageProfile  string  `json:"storage_profile"`
	StorageDevice   string  `json:"storage_device,omitempty"`
	Gateway         Gateway `json:"gateway"`
	// LogicalProxmoxIdentity is the fixed boetticher platform identity. The
	// live Proxmox API node identifier is discovered per invocation and is not
	// part of operator-authored configuration or the API path binding.
	LogicalProxmoxIdentity string                  `json:"logical_proxmox_identity"`
	BootstrapAddress       string                  `json:"bootstrap_address,omitempty"`
	SSHIdentityFile        string                  `json:"ssh_identity_file,omitempty"`
	PhysicalNetwork        PhysicalNetwork         `json:"physical_network"`
	TestedVersions         TestedVersions          `json:"tested_versions"`
	Network                Network                 `json:"network"`
	PKI                    PKIMetadata             `json:"pki"`
	SecretMetadata         SecretMetadata          `json:"secret_metadata"`
	Ownership              OwnershipPolicy         `json:"ownership"`
	Components             []Component             `json:"components"`
	Modules                []ResolvedModule        `json:"modules,omitempty"`
	ModuleConfig           map[string]ModuleConfig `json:"module_config,omitempty"`
	Declarations           []ModuleDeclaration     `json:"declarations,omitempty"`
	RetainedModules        []RetainedModule        `json:"retained_modules,omitempty"`
}

type TestedVersions struct {
	Gateway string `yaml:"gateway" json:"gateway"`
	Zabbix  string `yaml:"zabbix" json:"zabbix"`
}

type Gateway struct {
	Mode string `yaml:"mode" json:"mode" jsonschema:"enum=managed,enum=external"`
}

type Network struct {
	Domain string `yaml:"domain" json:"domain"`
	Zones  []Zone `yaml:"zones" json:"zones"`
}

// PhysicalNetwork stores installation-specific hardware bindings separately
// from the fixed logical architecture. Observed speed, carrier, and current
// interface names are generated evidence; stable MAC/PCI identity is the
// reconciliation key.
type PhysicalNetwork struct {
	Upstream PhysicalNIC `yaml:"upstream" json:"upstream"`
	Trunk    PhysicalNIC `yaml:"trunk" json:"trunk"`
	Mode     string      `yaml:"mode" json:"mode" jsonschema:"enum=virtual-only,enum=physical-trunk"`
}

type PhysicalNIC struct {
	Name         string `yaml:"name,omitempty" json:"name,omitempty"`
	PermanentMAC string `yaml:"permanent_mac,omitempty" json:"permanent_mac,omitempty"`
	PCIAddress   string `yaml:"pci_address,omitempty" json:"pci_address,omitempty"`
}

type Zone struct {
	Name         string   `yaml:"name" json:"name"`
	VLAN         int      `yaml:"vlan" json:"vlan"`
	Network      string   `yaml:"network" json:"network"`
	Gateway      string   `yaml:"gateway" json:"gateway"`
	AddressMode  string   `yaml:"address_mode" json:"address_mode"`
	DNSAddresses []string `yaml:"dns_addresses" json:"dns_addresses"`
	NTPAddresses []string `yaml:"ntp_addresses" json:"ntp_addresses"`
}

type SecretMetadata struct {
	InstallationID string `yaml:"installation_id" json:"installation_id"`
	AgeRecipient   string `yaml:"age_recipient" json:"age_recipient"`
}

type OwnershipPolicy struct {
	PlatformGuestIDMin   int  `yaml:"platform_guest_id_min" json:"platform_guest_id_min"`
	PlatformGuestIDMax   int  `yaml:"platform_guest_id_max" json:"platform_guest_id_max"`
	ModuleGuestIDMin     int  `yaml:"module_guest_id_min" json:"module_guest_id_min"`
	ModuleGuestIDMax     int  `yaml:"module_guest_id_max" json:"module_guest_id_max"`
	UserGuestIDMin       int  `yaml:"user_guest_id_min" json:"user_guest_id_min"`
	UserGuestIDMax       int  `yaml:"user_guest_id_max" json:"user_guest_id_max"`
	UserWorkloadsManaged bool `yaml:"user_workloads_managed" json:"user_workloads_managed"`
}

type PKIMetadata struct {
	RootCommonName     string `yaml:"root_common_name" json:"root_common_name"`
	RootFingerprint    string `yaml:"root_fingerprint" json:"root_fingerprint"`
	RootExpiry         string `yaml:"root_expiry" json:"root_expiry"`
	IssuingCommonName  string `yaml:"issuing_common_name" json:"issuing_common_name"`
	IssuingFingerprint string `yaml:"issuing_fingerprint" json:"issuing_fingerprint"`
	IssuingExpiry      string `yaml:"issuing_expiry" json:"issuing_expiry"`
}

// Component is a declared boetticher platform resource. Components are the
// only resources that the core projections may create or continuously manage.
type Component struct {
	Name         string   `json:"name"`
	VMID         int      `json:"vmid,omitempty"`
	Hostname     string   `json:"hostname"`
	Zone         string   `json:"zone"`
	Address      string   `json:"address"`
	Role         string   `json:"role"`
	DNSAliases   []string `json:"dns_aliases,omitempty"`
	URL          string   `json:"url,omitempty"`
	SSHUser      string   `json:"ssh_user,omitempty"`
	SSHPort      int      `json:"ssh_port,omitempty"`
	Monitoring   bool     `json:"monitoring"`
	Backup       bool     `json:"backup"`
	Tags         []string `json:"tags,omitempty"`
	MTLS         bool     `json:"mtls"`
	SSHManaged   bool     `json:"ssh_managed"`
	JumpAllowed  bool     `json:"jump_allowed"`
	ProductOwned bool     `json:"product_owned"`
	Module       string   `json:"module,omitempty"`
	Logging      bool     `json:"logging"`
}

type ModuleConfig struct {
	Enabled  *bool  `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Provider string `yaml:"provider,omitempty" json:"provider,omitempty"`
}

type DNSProvider string

const (
	DNSProviderBlocky  DNSProvider = "blocky"
	DNSProviderAdGuard DNSProvider = "adguard"
)

// ResolvedModule is generated state, not an operator-maintained module list.
// It records why a first-party module is active and which contracts it
// participates in after composition.
type ResolvedModule struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Policy    string   `json:"policy"`
	Enabled   bool     `json:"enabled"`
	Reason    string   `json:"reason"`
	State     string   `json:"state"`
	DependsOn []string `json:"depends_on,omitempty"`
	Requires  []string `json:"requires,omitempty"`
	Provides  []string `json:"provides,omitempty"`
}

type Artifact struct {
	Name             string `json:"name"`
	Version          string `json:"version"`
	Provider         string `json:"provider,omitempty"`
	Architecture     string `json:"architecture"`
	Kind             string `json:"kind"`
	DefinitionSHA256 string `json:"definition_sha256"`
	ContentSHA256    string `json:"content_sha256,omitempty"`
}

type StoragePlacement string

const (
	StorageDefault         StoragePlacement = "default"
	StoragePreferDataDisk  StoragePlacement = "prefer-data-disk"
	StorageRequireDataDisk StoragePlacement = "require-data-disk"
)

type PersistentVolumeDeclaration struct {
	Name      string           `json:"name"`
	Module    string           `json:"module"`
	Guest     string           `json:"guest"`
	SizeGiB   int              `json:"size_gib"`
	MountPath string           `json:"mount_path"`
	Placement StoragePlacement `json:"placement"`
	Backup    bool             `json:"backup"`
	Storage   string           `json:"storage,omitempty"`
}

type PersistentState struct {
	Name        string `json:"name"`
	Guest       string `json:"guest"`
	Path        string `json:"path"`
	Kind        string `json:"kind"`
	Backup      bool   `json:"backup"`
	Sensitive   bool   `json:"sensitive"`
	Replacement string `json:"replacement"`
}

type SecretDeclaration struct {
	Name       string `json:"name"`
	Purpose    string `json:"purpose"`
	Consumer   string `json:"consumer"`
	Generation string `json:"generation"`
	Rotation   string `json:"rotation"`
	Delivery   string `json:"delivery"`
	Persistent bool   `json:"persistent"`
}

type NetworkIntent struct {
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Protocol    string   `json:"protocol"`
	Ports       []string `json:"ports,omitempty"`
	Direction   string   `json:"direction"`
	Purpose     string   `json:"purpose"`
}

type DNSRecord struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Address string `json:"address"`
	Owner   string `json:"owner"`
}

type CertificateRequest struct {
	Identity string   `json:"identity"`
	SANs     []string `json:"sans"`
	Consumer string   `json:"consumer"`
}

type MonitoringDeclaration struct {
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Target      string   `json:"target"`
	Checks      []string `json:"checks,omitempty"`
	Description string   `json:"description"`
}

type BackupDeclaration struct {
	Guest  string `json:"guest"`
	Policy string `json:"policy"`
}

type PortalEntry struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	URLs        []string `json:"urls,omitempty"`
	Docs        []string `json:"docs,omitempty"`
}

type ModuleDeclaration struct {
	Module         string                        `json:"module"`
	Artifact       Artifact                      `json:"artifact"`
	Guests         []Component                   `json:"guests,omitempty"`
	Persistent     []PersistentState             `json:"persistent,omitempty"`
	Volumes        []PersistentVolumeDeclaration `json:"volumes,omitempty"`
	Secrets        []SecretDeclaration           `json:"secrets,omitempty"`
	NetworkIntents []NetworkIntent               `json:"network_intents,omitempty"`
	DNSRecords     []DNSRecord                   `json:"dns_records,omitempty"`
	Certificates   []CertificateRequest          `json:"certificates,omitempty"`
	Monitoring     []MonitoringDeclaration       `json:"monitoring,omitempty"`
	Backups        []BackupDeclaration           `json:"backups,omitempty"`
	Portal         []PortalEntry                 `json:"portal,omitempty"`
}

type RetainedModule struct {
	Module      string            `json:"module"`
	Disposition string            `json:"disposition"`
	Active      bool              `json:"active"`
	Guests      []Component       `json:"guests,omitempty"`
	Persistent  []PersistentState `json:"persistent,omitempty"`
}

func NewDefaultSite(installationID, ageRecipient string) Site {
	site := NewSite(installationID, ageRecipient, GatewayModeManaged)
	// NewDefaultSite is also the in-memory fixture constructor used by core
	// provider tests. The persisted SiteConfig path is composed by modules;
	// this fixture keeps the provider tests useful without making those
	// components part of NewSite's Core-owned canonical seed.
	for _, component := range []Component{
		{Name: "lab-fw-01", VMID: ProxmoxVMID, Hostname: "lab-fw-01", Zone: "MGMT", Address: "10.10.99.1", Role: "Debian firewall", Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true, Module: "firewall"},
		{Name: "lab-dns-01", VMID: DNS01VMID, Hostname: "lab-dns-01", Zone: "SERVERS", Address: "10.10.20.10", Role: "DNS/NTP", DNSAliases: []string{"dns01", "dns"}, Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true, Module: "dns"},
		{Name: "lab-dns-02", VMID: DNS02VMID, Hostname: "lab-dns-02", Zone: "SERVERS", Address: "10.10.20.11", Role: "DNS/NTP", DNSAliases: []string{"dns02"}, Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true, Module: "dns"},
		{Name: "lab-monitor-01", VMID: MonitorVMID, Hostname: "lab-monitor-01", Zone: "SERVERS", Address: "10.10.20.20", Role: "Zabbix", DNSAliases: []string{"monitor"}, URL: "https://monitor." + DefaultDomain, Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true, Module: "monitoring"},
		{Name: "lab-log-01", VMID: LoggingVMID, Hostname: "lab-log-01", Zone: "SERVERS", Address: "10.10.20.40", Role: "Central systemd journal", DNSAliases: []string{"logs"}, Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true, Module: "logging"},
	} {
		component.Tags = []string{TagBoetticher, TagManaged, TagModule, "module-" + component.Module, ModuleOwnershipTag(component.Module), TagBackup}
		component.SSHUser, component.SSHPort = DefaultAdminSSHUser, 22
		component.Logging = component.Module != "logging"
		site.Components = append(site.Components, component)
	}
	return site
}

func NewSite(installationID, ageRecipient, gatewayMode string) Site {
	site := Site{
		APIVersion:             APIVersion,
		PlatformVersion:        PlatformVersion,
		SchemaVersion:          SchemaVersion,
		StorageProfile:         "single-disk",
		Gateway:                Gateway{Mode: gatewayMode},
		LogicalProxmoxIdentity: LogicalProxmoxIdentity,
		TestedVersions: TestedVersions{
			Gateway: QualifiedGatewayImage,
			Zabbix:  ZabbixSeries,
		},
		Network: Network{
			Domain: DefaultDomain,
			Zones: []Zone{
				{Name: "TRUSTED", VLAN: 10, Network: "10.10.10.0/24", Gateway: "10.10.10.1", AddressMode: "dynamic-reservations", DNSAddresses: []string{"10.10.20.10", "10.10.20.11"}, NTPAddresses: []string{"10.10.20.10", "10.10.20.11"}},
				{Name: "SERVERS", VLAN: 20, Network: "10.10.20.0/24", Gateway: "10.10.20.1", AddressMode: "dynamic-reservations", DNSAddresses: []string{"10.10.20.10", "10.10.20.11"}, NTPAddresses: []string{"10.10.20.10", "10.10.20.11"}},
				{Name: "SANDBOX", VLAN: 50, Network: "10.10.50.0/24", Gateway: "10.10.50.1", AddressMode: "dynamic", DNSAddresses: []string{"10.10.50.1"}, NTPAddresses: []string{"10.10.50.1"}},
				{Name: "MGMT", VLAN: 99, Network: "10.10.99.0/24", Gateway: "10.10.99.1", AddressMode: "reservations-only", DNSAddresses: []string{"10.10.20.10", "10.10.20.11"}, NTPAddresses: []string{"10.10.20.10", "10.10.20.11"}},
			},
		},
		PhysicalNetwork: PhysicalNetwork{Mode: ModeVirtualOnly},
		SecretMetadata:  SecretMetadata{InstallationID: installationID, AgeRecipient: ageRecipient},
		Ownership: OwnershipPolicy{
			PlatformGuestIDMin: PlatformGuestIDMin, PlatformGuestIDMax: PlatformGuestIDMax,
			ModuleGuestIDMin: ModuleGuestIDMin, ModuleGuestIDMax: ModuleGuestIDMax,
			UserGuestIDMin: UserGuestIDMin, UserGuestIDMax: UserGuestIDMax,
			UserWorkloadsManaged: false,
		},
		Components: []Component{
			{Name: "lab-proxmox-01", Hostname: "lab-proxmox-01", Zone: "MGMT", Address: "10.10.99.5", Role: "Proxmox host", Tags: []string{TagBoetticher, TagManaged, TagPlatform, TagInfra, TagNetwork}, URL: "https://proxmox." + DefaultDomain + ":8006", Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: false, ProductOwned: true, SSHUser: DefaultAdminSSHUser, SSHPort: 22, Logging: true},
			{Name: "lab-portal-01", VMID: PortalVMID, Hostname: "lab-portal-01", Zone: "SERVERS", Address: "10.10.20.30", Role: "Generated platform portal", Tags: []string{TagBoetticher, TagManaged, TagPlatform, TagInfra, TagPortal, TagCorePortal, TagBackup}, URL: "https://portal." + DefaultDomain, DNSAliases: []string{"portal"}, SSHUser: DefaultAdminSSHUser, SSHPort: 22, Monitoring: true, Backup: true, MTLS: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true, Logging: true},
		},
	}
	return site
}

func (s Site) Normalize() Site {
	copySite := s
	copySite.Network.Zones = append([]Zone(nil), s.Network.Zones...)
	copySite.Components = append([]Component(nil), s.Components...)
	copySite.Modules = append([]ResolvedModule(nil), s.Modules...)
	copySite.ModuleConfig = cloneModuleConfig(s.ModuleConfig)
	copySite.Declarations = append([]ModuleDeclaration(nil), s.Declarations...)
	copySite.RetainedModules = append([]RetainedModule(nil), s.RetainedModules...)
	sort.Slice(copySite.Network.Zones, func(i, j int) bool { return copySite.Network.Zones[i].VLAN < copySite.Network.Zones[j].VLAN })
	sort.Slice(copySite.Components, func(i, j int) bool { return copySite.Components[i].Name < copySite.Components[j].Name })
	sort.Slice(copySite.Modules, func(i, j int) bool { return copySite.Modules[i].Name < copySite.Modules[j].Name })
	sort.Slice(copySite.Declarations, func(i, j int) bool { return copySite.Declarations[i].Module < copySite.Declarations[j].Module })
	sort.Slice(copySite.RetainedModules, func(i, j int) bool { return copySite.RetainedModules[i].Module < copySite.RetainedModules[j].Module })
	for i := range copySite.Components {
		copySite.Components[i].DNSAliases = append([]string(nil), copySite.Components[i].DNSAliases...)
		sort.Strings(copySite.Components[i].DNSAliases)
		copySite.Components[i].Tags = append([]string(nil), copySite.Components[i].Tags...)
		sort.Strings(copySite.Components[i].Tags)
	}
	for i := range copySite.Declarations {
		sort.Slice(copySite.Declarations[i].Guests, func(a, b int) bool {
			return copySite.Declarations[i].Guests[a].Name < copySite.Declarations[i].Guests[b].Name
		})
		sort.Slice(copySite.Declarations[i].Persistent, func(a, b int) bool {
			return copySite.Declarations[i].Persistent[a].Name < copySite.Declarations[i].Persistent[b].Name
		})
		sort.Slice(copySite.Declarations[i].Volumes, func(a, b int) bool {
			return copySite.Declarations[i].Volumes[a].Name < copySite.Declarations[i].Volumes[b].Name
		})
		sort.Slice(copySite.Declarations[i].Secrets, func(a, b int) bool {
			return copySite.Declarations[i].Secrets[a].Name < copySite.Declarations[i].Secrets[b].Name
		})
		sort.Slice(copySite.Declarations[i].DNSRecords, func(a, b int) bool {
			return copySite.Declarations[i].DNSRecords[a].Name < copySite.Declarations[i].DNSRecords[b].Name
		})
	}
	return copySite
}

func (s Site) Validate() error {
	if s.APIVersion != APIVersion || s.SchemaVersion != SchemaVersion {
		return fmt.Errorf("site schema %q/%d is not supported by boetticher v0.3; recreate the site with boetticher init", s.APIVersion, s.SchemaVersion)
	}
	if s.PlatformVersion == "" {
		return errors.New("platform_version is required")
	}
	if s.StorageProfile != "single-disk" && s.StorageProfile != "dedicated-data-disk" {
		return fmt.Errorf("unsupported storage_profile %q", s.StorageProfile)
	}
	if s.StorageProfile == "dedicated-data-disk" {
		if !strings.HasPrefix(s.StorageDevice, "/dev/disk/by-id/") || strings.ContainsAny(s.StorageDevice, "\r\n'\" \t") {
			return errors.New("dedicated-data-disk requires a stable /dev/disk/by-id device identity")
		}
	} else if s.StorageDevice != "" {
		return errors.New("storage_device is only valid for dedicated-data-disk")
	}
	if s.Gateway.Mode != GatewayModeManaged && s.Gateway.Mode != GatewayModeExternal {
		return fmt.Errorf("gateway.mode must be managed or external")
	}
	if s.Network.Domain != DefaultDomain {
		return fmt.Errorf("network.domain must be %s", DefaultDomain)
	}
	if s.TestedVersions.Gateway != QualifiedGatewayImage {
		return fmt.Errorf("tested_versions.gateway must equal the qualified image %q", QualifiedGatewayImage)
	}
	if s.TestedVersions.Zabbix != ZabbixSeries {
		return fmt.Errorf("tested_versions.zabbix must be %q", ZabbixSeries)
	}
	if s.PhysicalNetwork.Mode != ModeVirtualOnly && s.PhysicalNetwork.Mode != ModePhysicalTrunk {
		return fmt.Errorf("physical_network.mode must be virtual-only or physical-trunk")
	}
	if s.PhysicalNetwork.Mode == ModeVirtualOnly && s.PhysicalNetwork.Trunk.Name != "" {
		return errors.New("virtual-only physical network mode cannot retain a trunk binding")
	}
	if s.PhysicalNetwork.Mode == ModePhysicalTrunk && s.PhysicalNetwork.Upstream.Name == "" {
		return errors.New("physical-trunk mode requires an upstream interface identity")
	}
	for label, nic := range map[string]PhysicalNIC{"upstream": s.PhysicalNetwork.Upstream, "trunk": s.PhysicalNetwork.Trunk} {
		if nic.Name != "" && !safeInterfaceName(nic.Name) {
			return fmt.Errorf("physical_network.%s.name is not a safe interface name", label)
		}
		if nic.PermanentMAC != "" {
			if parsed, err := net.ParseMAC(nic.PermanentMAC); err != nil || len(parsed) != 6 {
				return fmt.Errorf("physical_network.%s.permanent_mac is not an Ethernet MAC", label)
			}
		}
		if strings.ContainsAny(nic.PCIAddress, "\r\n") {
			return fmt.Errorf("physical_network.%s.pci_address contains a newline", label)
		}
		if nic.Name != "" && nic.PermanentMAC == "" && nic.PCIAddress == "" {
			return fmt.Errorf("physical_network.%s requires a stable MAC or PCI identity", label)
		}
	}
	if s.PhysicalNetwork.Mode == ModePhysicalTrunk && s.PhysicalNetwork.Trunk.Name == "" {
		return errors.New("physical-trunk mode requires a persisted trunk interface identity")
	}
	if s.Ownership != (OwnershipPolicy{PlatformGuestIDMin: PlatformGuestIDMin, PlatformGuestIDMax: PlatformGuestIDMax, ModuleGuestIDMin: ModuleGuestIDMin, ModuleGuestIDMax: ModuleGuestIDMax, UserGuestIDMin: UserGuestIDMin, UserGuestIDMax: UserGuestIDMax, UserWorkloadsManaged: false}) {
		return errors.New("ownership policy must reserve 100-199 for platform, 200-499 for official modules, and 500-899 for user workloads; user workloads are not managed")
	}
	if s.SecretMetadata.InstallationID == "" || s.SecretMetadata.AgeRecipient == "" {
		return fmt.Errorf("secret_metadata must contain installation_id and public age_recipient")
	}
	expectedZones := map[string]struct {
		vlan    int
		network string
		gateway string
	}{
		"TRUSTED": {vlan: 10, network: "10.10.10.0/24", gateway: "10.10.10.1"},
		"SERVERS": {vlan: 20, network: "10.10.20.0/24", gateway: "10.10.20.1"},
		"SANDBOX": {vlan: 50, network: "10.10.50.0/24", gateway: "10.10.50.1"},
		"MGMT":    {vlan: 99, network: "10.10.99.0/24", gateway: "10.10.99.1"},
	}
	seenZones := map[string]bool{}
	for _, z := range s.Network.Zones {
		if seenZones[z.Name] {
			return fmt.Errorf("duplicate zone %q", z.Name)
		}
		seenZones[z.Name] = true
		expected, ok := expectedZones[z.Name]
		if !ok || z.VLAN != expected.vlan || z.Network != expected.network || z.Gateway != expected.gateway {
			return fmt.Errorf("zone %s does not match the fixed V1 network contract", z.Name)
		}
		if _, _, err := net.ParseCIDR(z.Network); err != nil {
			return fmt.Errorf("zone %s has invalid network: %w", z.Name, err)
		}
	}
	seenComponents := map[string]bool{}
	seenVMIDs := map[int]string{}
	for _, m := range s.Components {
		if m.Name == "" || m.Hostname == "" || m.Address == "" || m.Zone == "" {
			return fmt.Errorf("component %q is missing name, hostname, zone, or address", m.Name)
		}
		for field, value := range map[string]string{"name": m.Name, "hostname": m.Hostname, "zone": m.Zone, "ssh_user": m.SSHUser} {
			if value != "" && !modelTokenPattern.MatchString(value) {
				return fmt.Errorf("component %s has unsafe %s", m.Name, field)
			}
		}
		for _, alias := range m.DNSAliases {
			if !modelTokenPattern.MatchString(alias) {
				return fmt.Errorf("component %s has unsafe DNS alias %q", m.Name, alias)
			}
		}
		seenTags := map[string]bool{}
		for _, tag := range m.Tags {
			if !modelTokenPattern.MatchString(tag) || tag != strings.ToLower(tag) {
				return fmt.Errorf("component %s has unsafe tag %q", m.Name, tag)
			}
			if seenTags[tag] {
				return fmt.Errorf("component %s has duplicate tag %q", m.Name, tag)
			}
			seenTags[tag] = true
		}
		if m.ProductOwned {
			for _, requiredTag := range []string{TagBoetticher, TagManaged} {
				if !seenTags[requiredTag] {
					return fmt.Errorf("platform component %s is missing required tag %q", m.Name, requiredTag)
				}
			}
			if m.VMID != 0 && m.Backup && !seenTags[TagBackup] {
				return fmt.Errorf("platform guest %s is marked for backup but is missing required tag %q", m.Name, TagBackup)
			}
		}
		if strings.ContainsAny(m.Role+m.URL, "\r\n") {
			return fmt.Errorf("component %s contains a newline in generated metadata", m.Name)
		}
		if seenComponents[m.Name] {
			return fmt.Errorf("duplicate component %q", m.Name)
		}
		seenComponents[m.Name] = true
		if m.VMID != 0 {
			if previous, exists := seenVMIDs[m.VMID]; exists {
				return fmt.Errorf("components %s and %s share VMID %d", previous, m.Name, m.VMID)
			}
			seenVMIDs[m.VMID] = m.Name
			if m.ProductOwned && (m.VMID < PlatformGuestIDMin || m.VMID > ModuleGuestIDMax) {
				return fmt.Errorf("platform component %s uses VMID %d outside boetticher-owned ranges", m.Name, m.VMID)
			}
			if !m.ProductOwned && (m.VMID < UserGuestIDMin || m.VMID > UserGuestIDMax) {
				return fmt.Errorf("user-managed component %s uses VMID %d outside the reserved user-workload range", m.Name, m.VMID)
			}
		}
		if ip := net.ParseIP(m.Address); ip == nil || ip.To4() == nil {
			return fmt.Errorf("component %s has invalid IPv4 address %q", m.Name, m.Address)
		}
		if !seenZones[m.Zone] {
			return fmt.Errorf("component %s references unknown zone %q", m.Name, m.Zone)
		}
	}
	if len(seenZones) != len(expectedZones) {
		return fmt.Errorf("V1 requires exactly TRUSTED, SERVERS, SANDBOX, and MGMT zones")
	}
	requiredComponents := map[string]struct {
		address string
		vmid    int
	}{
		"lab-proxmox-01": {address: "10.10.99.5", vmid: 0},
		"lab-portal-01":  {address: "10.10.20.30", vmid: PortalVMID},
	}
	composed := len(s.Declarations) > 0
	for _, component := range s.Components {
		if component.Module != "" {
			composed = true
		}
	}
	if composed {
		requiredComponents["lab-dns-01"] = struct {
			address string
			vmid    int
		}{address: "10.10.20.10", vmid: DNS01VMID}
		requiredComponents["lab-dns-02"] = struct {
			address string
			vmid    int
		}{address: "10.10.20.11", vmid: DNS02VMID}
	}
	if composed && resolvedModuleEnabled(s.Modules, "monitoring", true) {
		requiredComponents["lab-monitor-01"] = struct {
			address string
			vmid    int
		}{address: "10.10.20.20", vmid: MonitorVMID}
	}
	if composed && resolvedModuleEnabled(s.Modules, "logging", true) {
		requiredComponents["lab-log-01"] = struct {
			address string
			vmid    int
		}{address: "10.10.20.40", vmid: LoggingVMID}
	}
	if composed && s.Gateway.Mode == GatewayModeManaged && resolvedModuleEnabled(s.Modules, "firewall", true) {
		requiredComponents["lab-fw-01"] = struct {
			address string
			vmid    int
		}{address: "10.10.99.1", vmid: ProxmoxVMID}
	} else if composed {
		for _, component := range s.Components {
			if component.Name == "lab-fw-01" {
				return errors.New("external gateway mode must not declare lab-fw-01")
			}
		}
	}
	for required, expected := range requiredComponents {
		found, ok := seenComponents[required]
		if !ok || !found {
			return fmt.Errorf("required foundation component %q is missing", required)
		}
		for _, m := range s.Components {
			if m.Name == required && (m.Address != expected.address || m.VMID != expected.vmid || !m.ProductOwned) {
				return fmt.Errorf("foundation component %s must use address %s, VMID %d, and platform ownership", required, expected.address, expected.vmid)
			}
		}
	}
	seenModules := map[string]bool{}
	for _, module := range s.Modules {
		if module.Name == "" || !modelTokenPattern.MatchString(module.Name) {
			return fmt.Errorf("official module has unsafe name %q", module.Name)
		}
		if seenModules[module.Name] {
			return fmt.Errorf("duplicate official module %q", module.Name)
		}
		seenModules[module.Name] = true
	}
	if err := validateDeclarations(s); err != nil {
		return err
	}
	return nil
}

func validateDeclarations(s Site) error {
	seenVMIDs := map[int]string{}
	seenNames := map[string]string{}
	seenAddresses := map[string]string{}
	for _, declaration := range s.Declarations {
		if declaration.Module == "" {
			return errors.New("module declaration is missing its owner")
		}
		if len(declaration.Artifact.DefinitionSHA256) != 64 {
			return fmt.Errorf("module %s has incomplete artifact definition digest metadata", declaration.Module)
		}
		for _, guest := range declaration.Guests {
			if guest.Module != declaration.Module {
				return fmt.Errorf("guest %s has owner %q but is declared by module %q", guest.Name, guest.Module, declaration.Module)
			}
			if previous, exists := seenVMIDs[guest.VMID]; exists && guest.VMID != 0 {
				return fmt.Errorf("module guest VMID %d is declared by both %s and %s", guest.VMID, previous, declaration.Module)
			}
			if guest.VMID != 0 {
				seenVMIDs[guest.VMID] = declaration.Module
			}
			if previous, exists := seenNames[guest.Hostname]; exists && previous != declaration.Module {
				return fmt.Errorf("module hostname %q collides between %s and %s", guest.Hostname, previous, declaration.Module)
			}
			seenNames[guest.Hostname] = declaration.Module
			if previous, exists := seenAddresses[guest.Address]; exists && guest.Address != "" && previous != declaration.Module {
				return fmt.Errorf("module address %q collides between %s and %s", guest.Address, previous, declaration.Module)
			}
			if guest.Address != "" {
				seenAddresses[guest.Address] = declaration.Module
			}
		}
		for _, state := range declaration.Persistent {
			if state.Replacement == "" {
				return fmt.Errorf("module %s persistent state %q is missing a replacement policy", declaration.Module, state.Name)
			}
		}
		for _, volume := range declaration.Volumes {
			if volume.Module != declaration.Module || volume.Guest == "" || volume.Name == "" || volume.SizeGiB <= 0 || volume.MountPath == "" {
				return fmt.Errorf("module %s has invalid persistent volume %q", declaration.Module, volume.Name)
			}
			switch volume.Placement {
			case StorageDefault, StoragePreferDataDisk, StorageRequireDataDisk:
			default:
				return fmt.Errorf("module %s volume %s has unsupported storage placement %q", declaration.Module, volume.Name, volume.Placement)
			}
		}
	}
	return nil
}

func resolvedModuleEnabled(modules []ResolvedModule, name string, defaultValue bool) bool {
	if len(modules) == 0 {
		return defaultValue
	}
	for _, module := range modules {
		if module.Name == name {
			return module.Enabled
		}
	}
	return defaultValue
}

func (s Site) PlatformComponents() []Component {
	components := make([]Component, 0)
	for _, component := range s.Components {
		if component.ProductOwned && (len(s.Declarations) == 0 || component.Module == "") {
			components = append(components, component)
		}
	}
	if len(s.Declarations) > 0 {
		for _, declaration := range s.Declarations {
			components = append(components, declaration.Guests...)
		}
	}
	sort.Slice(components, func(i, j int) bool { return components[i].Name < components[j].Name })
	return components
}

func safeInterfaceName(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !(r == '.' || r == '-' || r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func (s Site) CanonicalJSON() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	canonical := s.Normalize()
	// The operator's local private-key path affects generated client config,
	// not the platform desired state or its model revision.
	canonical.SSHIdentityFile = ""
	return json.Marshal(canonical)
}

func (s Site) Revision() (string, error) {
	b, err := s.CanonicalJSON()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func ExpandUserPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return home + path[1:]
		}
	}
	return path
}
