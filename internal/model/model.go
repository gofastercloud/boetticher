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
	SchemaVersion               = 3
	PlatformVersion             = "0.3.0"
	QualifiedGatewayImage       = "debian-13-genericcloud-amd64"
	QualifiedGatewayImageURL    = "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2"
	QualifiedGatewayImageSHA512 = "77429b411b39b43f914dc9d14bf34aa315489a1a12b5429f72e5b483bdda23c65698d33443c85d3f3ad7c3a0828ae60845406d6b99646342554d17abae29c2a3"
	ZabbixSeries                = "7.0 LTS"
	AuthoritativeDNS            = "PowerDNS Authoritative"
	AuthoritativeDNSVersion     = "4.9.17"
	AuthoritativePackageVersion = "4.9.17-1pdns.bookworm"
	DefaultDomain               = "lab.home.arpa"
	DefaultSiteDir              = "my-boetticher"
	DefaultAgeIdentity          = "~/.config/boetticher/age/identity.txt"
	DefaultSSHConfig            = "~/.ssh/config.d/boetticher.conf"
	DefaultAdminSSHUser         = "labadmin"
	DefaultProxmoxNode          = "lab-proxmox-01"
	ProxmoxVMID                 = 100
	DNS01VMID                   = 110
	DNS02VMID                   = 111
	MonitorVMID                 = 120
	PortalVMID                  = 130
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
)

var modelTokenPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,253}$`)

type Site struct {
	APIVersion       string                  `json:"api_version"`
	PlatformVersion  string                  `json:"platform_version"`
	SchemaVersion    int                     `json:"schema_version"`
	StorageProfile   string                  `json:"storage_profile"`
	StorageDevice    string                  `json:"storage_device,omitempty"`
	Gateway          Gateway                 `json:"gateway"`
	ProxmoxNode      string                  `json:"proxmox_node"`
	BootstrapAddress string                  `json:"bootstrap_address,omitempty"`
	SSHIdentityFile  string                  `json:"ssh_identity_file,omitempty"`
	PhysicalNetwork  PhysicalNetwork         `json:"physical_network"`
	TestedVersions   TestedVersions          `json:"tested_versions"`
	Network          Network                 `json:"network"`
	PKI              PKIMetadata             `json:"pki"`
	SecretMetadata   SecretMetadata          `json:"secret_metadata"`
	Ownership        OwnershipPolicy         `json:"ownership"`
	Components       []Component             `json:"components"`
	Modules          []ResolvedModule        `json:"modules,omitempty"`
	ModuleConfig     map[string]ModuleConfig `json:"module_config,omitempty"`
	Declarations     []ModuleDeclaration     `json:"declarations,omitempty"`
}

type TestedVersions struct {
	Gateway string `yaml:"gateway" json:"gateway"`
	Zabbix  string `yaml:"zabbix" json:"zabbix"`
}

type Gateway struct {
	Mode string `yaml:"mode" json:"mode"`
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
	Mode     string      `yaml:"mode" json:"mode"`
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
}

type ModuleConfig struct {
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
}

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
	Architecture     string `json:"architecture"`
	Kind             string `json:"kind"`
	SHA256           string `json:"sha256"`
	DefinitionSHA256 string `json:"definition_sha256"`
}

type PersistentState struct {
	Name      string `json:"name"`
	Guest     string `json:"guest"`
	Path      string `json:"path"`
	Kind      string `json:"kind"`
	Backup    bool   `json:"backup"`
	Sensitive bool   `json:"sensitive"`
}

type SecretDeclaration struct {
	Name       string `json:"name"`
	Purpose    string `json:"purpose"`
	Consumer   string `json:"consumer"`
	Generation string `json:"generation"`
	Rotation   string `json:"rotation"`
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
	Module         string                  `json:"module"`
	Artifact       Artifact                `json:"artifact"`
	Guests         []Component             `json:"guests,omitempty"`
	Persistent     []PersistentState       `json:"persistent,omitempty"`
	Secrets        []SecretDeclaration     `json:"secrets,omitempty"`
	NetworkIntents []NetworkIntent         `json:"network_intents,omitempty"`
	DNSRecords     []DNSRecord             `json:"dns_records,omitempty"`
	Certificates   []CertificateRequest    `json:"certificates,omitempty"`
	Monitoring     []MonitoringDeclaration `json:"monitoring,omitempty"`
	Backups        []BackupDeclaration     `json:"backups,omitempty"`
	Portal         []PortalEntry           `json:"portal,omitempty"`
}

func NewDefaultSite(installationID, ageRecipient string) Site {
	return NewSite(installationID, ageRecipient, GatewayModeManaged)
}

func NewSite(installationID, ageRecipient, gatewayMode string) Site {
	site := Site{
		APIVersion:      "boetticher/v3",
		PlatformVersion: PlatformVersion,
		SchemaVersion:   SchemaVersion,
		StorageProfile:  "single-disk",
		Gateway:         Gateway{Mode: gatewayMode},
		ProxmoxNode:     DefaultProxmoxNode,
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
			{Name: "lab-proxmox-01", Hostname: "lab-proxmox-01", Zone: "MGMT", Address: "10.10.99.5", Role: "Proxmox host", Tags: []string{TagBoetticher, TagManaged, TagPlatform, TagInfra, TagNetwork}, URL: "https://proxmox." + DefaultDomain + ":8006", Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: false, ProductOwned: true, SSHUser: DefaultAdminSSHUser, SSHPort: 22},
			{Name: "lab-fw-01", VMID: ProxmoxVMID, Hostname: "lab-fw-01", Zone: "MGMT", Address: "10.10.99.1", Role: "Debian firewall", Tags: []string{TagBoetticher, TagManaged, TagPlatform, TagInfra, TagNetwork, TagFirewall, TagGateway, TagBackup}, Monitoring: true, Backup: true, MTLS: false, SSHUser: DefaultAdminSSHUser, SSHPort: 22, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
			{Name: "lab-dns-01", VMID: DNS01VMID, Hostname: "lab-dns-01", Zone: "SERVERS", Address: "10.10.20.10", Role: "DNS/NTP", Tags: []string{TagBoetticher, TagManaged, TagPlatform, TagInfra, TagDNS, TagNTP, TagBackup}, DNSAliases: []string{"dns01", "dns"}, SSHUser: DefaultAdminSSHUser, SSHPort: 22, Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
			{Name: "lab-dns-02", VMID: DNS02VMID, Hostname: "lab-dns-02", Zone: "SERVERS", Address: "10.10.20.11", Role: "DNS/NTP", Tags: []string{TagBoetticher, TagManaged, TagPlatform, TagInfra, TagDNS, TagNTP, TagBackup}, DNSAliases: []string{"dns02"}, SSHUser: DefaultAdminSSHUser, SSHPort: 22, Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
			{Name: "lab-monitor-01", VMID: MonitorVMID, Hostname: "lab-monitor-01", Zone: "MGMT", Address: "10.10.99.20", Role: "Zabbix", Tags: []string{TagBoetticher, TagManaged, TagPlatform, TagInfra, TagObservability, TagBackup}, URL: "https://monitor." + DefaultDomain, DNSAliases: []string{"monitor"}, SSHUser: DefaultAdminSSHUser, SSHPort: 22, Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
			{Name: "lab-portal-01", VMID: PortalVMID, Hostname: "lab-portal-01", Zone: "SERVERS", Address: "10.10.20.30", Role: "Generated platform portal", Tags: []string{TagBoetticher, TagManaged, TagPlatform, TagInfra, TagPortal, TagBackup}, URL: "https://portal." + DefaultDomain, DNSAliases: []string{"portal"}, SSHUser: DefaultAdminSSHUser, SSHPort: 22, Monitoring: true, Backup: true, MTLS: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
		},
	}
	if gatewayMode == GatewayModeExternal {
		filtered := make([]Component, 0, len(site.Components)-1)
		for _, component := range site.Components {
			if component.Name != "lab-fw-01" {
				filtered = append(filtered, component)
			}
		}
		site.Components = filtered
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
	sort.Slice(copySite.Network.Zones, func(i, j int) bool { return copySite.Network.Zones[i].VLAN < copySite.Network.Zones[j].VLAN })
	sort.Slice(copySite.Components, func(i, j int) bool { return copySite.Components[i].Name < copySite.Components[j].Name })
	sort.Slice(copySite.Modules, func(i, j int) bool { return copySite.Modules[i].Name < copySite.Modules[j].Name })
	sort.Slice(copySite.Declarations, func(i, j int) bool { return copySite.Declarations[i].Module < copySite.Declarations[j].Module })
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
	if s.APIVersion != "boetticher/v3" || s.SchemaVersion != SchemaVersion {
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
	if s.ProxmoxNode != DefaultProxmoxNode {
		return fmt.Errorf("proxmox_node must be %q in V1", DefaultProxmoxNode)
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
		"lab-dns-01":     {address: "10.10.20.10", vmid: DNS01VMID},
		"lab-dns-02":     {address: "10.10.20.11", vmid: DNS02VMID},
		"lab-portal-01":  {address: "10.10.20.30", vmid: PortalVMID},
	}
	if resolvedModuleEnabled(s.Modules, "monitoring", true) {
		requiredComponents["lab-monitor-01"] = struct {
			address string
			vmid    int
		}{address: "10.10.99.20", vmid: MonitorVMID}
	}
	if s.Gateway.Mode == GatewayModeManaged && resolvedModuleEnabled(s.Modules, "firewall", true) {
		requiredComponents["lab-fw-01"] = struct {
			address string
			vmid    int
		}{address: "10.10.99.1", vmid: ProxmoxVMID}
	} else {
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
		if component.ProductOwned {
			components = append(components, component)
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
