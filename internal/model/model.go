package model

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

const (
	APIVersion = "boetticher/v3"
	// ReleaseVersion identifies the controller/release line. It is distinct
	// from the persisted configuration schema, artifact ABI, and bundle format.
	ReleaseVersion              = "0.5.0"
	SchemaVersion               = 3
	ConfigSchemaVersion         = SchemaVersion
	ArtifactABIVersion          = "boetticher/artifact/v1"
	BundleFormatVersion         = "boetticher/release-bundle/v1"
	PlatformVersion             = ReleaseVersion
	QualifiedGatewayImage       = "debian-13-genericcloud-amd64-20260327-2429"
	QualifiedGatewayImageURL    = "https://cloud.debian.org/images/cloud/trixie/20260327-2429/debian-13-genericcloud-amd64-20260327-2429.qcow2"
	QualifiedGatewayImageSHA512 = "09559ec27d263997827dd8cddf76e97ea8e0f1803380aa501ea7eaa4b4968cd76ffef4ec7eb07ef1a9ccbeb0925a5020492ea9ed53eb167d62f3a2285039912c"
	PulseVersion                = "6.1.2"
	PulseReleaseURL             = "https://github.com/rcourtman/Pulse/releases/download/v6.1.2/pulse-v6.1.2-linux-amd64.tar.gz"
	PulseReleaseSHA256          = "844cd054bcfce528cbcf434d782e571791cc7b02ef2fe298cf138b1cab1087ea"
	PulseAgentVersion           = "6.1.2"
	PulseAgentReleaseURL        = "https://github.com/rcourtman/Pulse/releases/download/v6.1.2/pulse-agent-linux-amd64"
	PulseAgentReleaseSHA256     = "1f3cfda2b112e82f311f05673f750bc6e5cb05bd0f942f9b84d7612d56f1ba75"
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
	GatusVMID                   = 250
	PortalVMID                  = 130
	LoggingVMID                 = 140
	BuilderVMID                 = 190
	BuilderCacheOwnerVMID       = 191
	BuilderCacheStorage         = "local-lvm"
	BuilderCacheVolumeName      = "vm-191-boetticher-builder-cache"
	BuilderCacheDiskGiB         = 64
	PrinterVMID                 = 230
	StreamDeckVMID              = 220
	AirVPNGuestVMID             = 260
	ArrVMID                     = 270
	ArrDownloadsVolumeGiB       = 500
	ArrDownloadsMountPath       = "/var/lib/arr/downloads"
	BuilderCores                = 4
	BuilderMemoryMiB            = 8192
	BuilderDiskGiB              = 32
	BuilderMinimumFreeGiB       = 20
	BuilderMAC                  = "02:00:00:00:01:90"
	DefaultGatewayUpstreamMAC   = "02:00:00:00:01:01"
	BuilderGoVersion            = "1.26.5"
	BuilderGoURL                = "https://go.dev/dl/go1.26.5.linux-amd64.tar.gz"
	BuilderGoSHA256             = "5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053"
	TransitVLAN                 = 5
	TransitNetwork              = "10.10.5.0/24"
	TransitGateway              = "10.10.5.1"
	AirVPNGuestAddress          = "10.10.5.20"
	ArrGuestAddress             = "10.10.20.110"
	ArrGuestMAC                 = "02:00:00:00:02:10"
	InfraVLAN                   = 10
	InfraNetwork                = "10.10.10.0/24"
	InfraGateway                = "10.10.10.1"
	ProxmoxManagementAddress    = "10.10.99.5"
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
	TagMonitoringAgent          = "monitoring-agent"
)

const (
	PulseAgentARM64ReleaseURL    = "https://github.com/rcourtman/Pulse/releases/download/v6.1.2/pulse-agent-linux-arm64"
	PulseAgentARM64ReleaseSHA256 = "20d956ccc93ca5fc8273b0f9c37398cf19271604b40dc6fe3ed8cbd39bef7185"
)

var modelTokenPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,253}$`)
var networkPortPattern = regexp.MustCompile(`^[0-9]{1,5}(?:-[0-9]{1,5})?$`)
var providerModelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
var usbPortPattern = regexp.MustCompile(`^[0-9]+-[0-9]+(?:\.[0-9]+)*$`)
var usbIDPattern = regexp.MustCompile(`^[0-9a-f]{4}$`)

var bifrostSecretReferencePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// ValidateStableDevice accepts only one direct stable-device entry. Keeping
// the suffix to a single path component prevents lexical dot segments or
// repeated separators from resolving to a transient /dev device.
func ValidateStableDevice(device string) error {
	const prefix = "/dev/disk/by-id/"
	if !strings.HasPrefix(device, prefix) {
		return errors.New("dedicated storage requires a stable /dev/disk/by-id device identity")
	}
	suffix := strings.TrimPrefix(device, prefix)
	if suffix == "" || strings.ContainsAny(suffix, "/\\\r\n'\" \t") || suffix == "." || suffix == ".." {
		return errors.New("dedicated storage requires a direct stable /dev/disk/by-id device identity")
	}
	return nil
}

// IsDNSLabel is the shared narrow hostname-label predicate used by desired
// state and runtime lease/deletion validation.
func IsDNSLabel(value string) bool {
	return dnsLabelPattern.MatchString(strings.ToLower(value))
}

// BifrostSecretReferenceID is the one credential identity used by the
// controller-side credential path and the Ansible environment projection.
// Validation rejects distinct source references that share this identity.
func BifrostSecretReferenceID(reference string) string {
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

// ModuleOwnershipTag returns the single Proxmox-safe ownership proof used for
// every first-party module guest. Invalid names return an empty tag so callers
// fail closed instead of creating an ambiguous ownership representation.
func ModuleOwnershipTag(module string) string {
	if !modelTokenPattern.MatchString(module) {
		return ""
	}
	return "boetticher-module-" + module
}

// GenerateGatewayUpstreamMAC creates the durable identity used by the
// managed gateway's upstream NIC. It is generated once during init and then
// persisted in site.yml; retries only happen for the vanishingly unlikely
// case of a collision with another fixed boetticher NIC identity.
func GenerateGatewayUpstreamMAC() (string, error) {
	for attempt := 0; attempt < 16; attempt++ {
		var value [6]byte
		if _, err := rand.Read(value[:]); err != nil {
			return "", fmt.Errorf("generate gateway upstream MAC: %w", err)
		}
		value[0] &= 0xfe // unicast
		value[0] |= 0x02 // locally administered
		mac := net.HardwareAddr(value[:]).String()
		if !GatewayUpstreamMACConflicts(mac) {
			return mac, nil
		}
	}
	return "", errors.New("generate gateway upstream MAC: repeated collision with a managed NIC identity")
}

// GatewayInterfaceMAC returns the fixed MAC for one of the gateway's seven
// logical NIC positions. Position 1 is the historical default only for
// in-memory fixtures; initialized sites replace it with the generated
// upstream identity.
func GatewayInterfaceMAC(position int) string {
	if position < 1 || position > 7 {
		return ""
	}
	if position == 1 {
		return DefaultGatewayUpstreamMAC
	}
	return fmt.Sprintf("02:00:00:00:01:%02x", position)
}

func GatewayUpstreamMACConflicts(value string) bool {
	parsed, err := net.ParseMAC(value)
	if err != nil || len(parsed) != 6 {
		return true
	}
	canonical := strings.ToLower(parsed.String())
	for position := 2; position <= 7; position++ {
		if canonical == GatewayInterfaceMAC(position) {
			return true
		}
	}
	return canonical == strings.ToLower(BuilderMAC)
}

func ValidateGatewayUpstreamMAC(value string) error {
	parsed, err := net.ParseMAC(value)
	if err != nil || len(parsed) != 6 {
		return fmt.Errorf("gateway.upstream.mac must be an Ethernet MAC")
	}
	if parsed[0]&0x01 != 0 {
		return errors.New("gateway.upstream.mac must be unicast")
	}
	if parsed[0]&0x02 == 0 {
		return errors.New("gateway.upstream.mac must be locally administered")
	}
	if GatewayUpstreamMACConflicts(value) {
		return errors.New("gateway.upstream.mac collides with another boetticher-managed NIC")
	}
	return nil
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
	USBExports             []USBExportBinding      `json:"usb_exports,omitempty"`
	RetainedModules        []RetainedModule        `json:"retained_modules,omitempty"`
	DHCPReservations       []DHCPReservation       `json:"dhcp_reservations,omitempty"`
	DNSRecords             []UserDNSRecord         `json:"dns_records,omitempty"`
	UserFirewallRules      []UserFirewallRule      `json:"firewall_rules,omitempty"`
	PendingDNSDeletions    []DNSDeletion           `json:"-"`
}

type TestedVersions struct {
	Gateway string `yaml:"gateway" json:"gateway"`
	Pulse   string `yaml:"pulse" json:"pulse"`
}

type Gateway struct {
	// Mode selects the managed gateway or the external-firewall contract.
	Mode string `yaml:"mode" json:"mode" jsonschema:"enum=managed,enum=external" jsonschema_description:"Use Boetticher's managed gateway or publish a contract for an external firewall."`
	// Upstream describes the existing HOME-side connection used by the gateway.
	Upstream GatewayUpstream `yaml:"upstream" json:"upstream"`
	// Publish lists the small set of platform services that may be published upstream.
	Publish []GatewayPublication `yaml:"publish,omitempty" json:"publish,omitempty"`
}

type GatewayUpstream struct {
	// Mode is DHCP; the upstream network remains operator-managed.
	Mode string `yaml:"mode" json:"mode" jsonschema:"enum=dhcp" jsonschema_description:"Upstream address source; DHCP is the supported mode."`
	// MAC is the stable locally administered address reserved in upstream DHCP.
	MAC string `yaml:"mac" json:"mac"`
}

type GatewayPublication struct {
	Service string `yaml:"service" json:"service" jsonschema:"enum=dns"`
}

type Network struct {
	Domain string `yaml:"domain" json:"domain"`
	Zones  []Zone `yaml:"zones" json:"zones"`
}

// ZoneType is the stable architectural meaning of a network zone. Concrete
// names, VLANs, and interface names remain site-resolved implementation
// details; modules request this semantic type instead.
type ZoneType string

const (
	ZoneTypeTransit        ZoneType = "transit"
	ZoneTypeInfrastructure ZoneType = "infrastructure"
	ZoneTypeServers        ZoneType = "servers"
	ZoneTypeTrusted        ZoneType = "trusted"
	ZoneTypeSandbox        ZoneType = "sandbox"
	ZoneTypeManagement     ZoneType = "management"
)

// PhysicalNetwork stores installation-specific hardware bindings separately
// from the fixed logical architecture. Observed speed, carrier, and current
// interface names are generated evidence; stable MAC/PCI identity is the
// reconciliation key.
type PhysicalNetwork struct {
	// Upstream identifies the NIC carrying the Proxmox HOME connection.
	Upstream PhysicalNIC `yaml:"upstream" json:"upstream"`
	// Trunk identifies the explicitly selected internal VLAN trunk NIC.
	Trunk PhysicalNIC `yaml:"trunk" json:"trunk"`
	// Mode records virtual-only or explicitly selected physical-trunk setup.
	Mode string `yaml:"mode" json:"mode" jsonschema:"enum=virtual-only,enum=physical-trunk" jsonschema_description:"Use the safe virtual-only layout or an explicitly selected physical trunk."`
}

type PhysicalNIC struct {
	Name         string `yaml:"name,omitempty" json:"name,omitempty"`
	PermanentMAC string `yaml:"permanent_mac,omitempty" json:"permanent_mac,omitempty"`
	PCIAddress   string `yaml:"pci_address,omitempty" json:"pci_address,omitempty"`
}

type Zone struct {
	Name         string   `yaml:"name" json:"name"`
	Type         ZoneType `yaml:"type" json:"type" jsonschema:"enum=transit,enum=infrastructure,enum=servers,enum=trusted,enum=sandbox,enum=management"`
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
	MAC          string   `json:"mac,omitempty"`
}

type ModuleConfig struct {
	Enabled    *bool                   `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Network    ModuleNetworkMode       `yaml:"network,omitempty" json:"network,omitempty"`
	Servers    string                  `yaml:"servers,omitempty" json:"servers,omitempty"`
	ModelAlias string                  `yaml:"model_alias,omitempty" json:"model_alias,omitempty"`
	Upstreams  []BifrostUpstreamConfig `yaml:"upstreams,omitempty" json:"upstreams,omitempty"`
	Models     []BifrostModelConfig    `yaml:"models,omitempty" json:"models,omitempty"`
}

type USBExportBinding struct {
	Module      string `yaml:"module" json:"module"`
	Requirement string `yaml:"requirement" json:"requirement"`
	Port        string `yaml:"port" json:"port"`
	VendorID    string `yaml:"vendor_id" json:"vendor_id"`
	ProductID   string `yaml:"product_id" json:"product_id"`
	Serial      string `yaml:"serial,omitempty" json:"serial,omitempty"`
}

type USBRequirement struct {
	Name              string        `json:"name"`
	Guest             string        `json:"guest"`
	DeviceType        string        `json:"device_type"`
	Access            string        `json:"access"`
	Required          bool          `json:"required"`
	AllowedIdentities []USBIdentity `json:"allowed_identities"`
}

type USBIdentity struct {
	VendorID  string `json:"vendor_id"`
	ProductID string `json:"product_id"`
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
	Lifecycle  string `json:"lifecycle,omitempty"`
	Persistent bool   `json:"persistent"`
}

const (
	SecretLifecycleRuntime   = "runtime"
	SecretLifecycleBootstrap = "bootstrap"
)

type DeviceRequirement struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Type   string `json:"type"`
	Major  int    `json:"major"`
	Minor  int    `json:"minor"`
	Access string `json:"access"`
}

type GuestSecurityDeclaration struct {
	Unprivileged bool                `json:"unprivileged"`
	Devices      []DeviceRequirement `json:"devices,omitempty"`
	Capabilities []string            `json:"capabilities,omitempty"`
}

type NetworkIntent struct {
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Endpoint    string   `json:"endpoint,omitempty"`
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

// DHCPReservation is an operator-provided Kea identity for a user workload.
// VMID is optional lookup metadata; MAC remains the network identity and this
// model never gives boetticher ownership of the guest.
type DHCPReservation struct {
	Zone     string `yaml:"zone" json:"zone"`
	Hostname string `yaml:"hostname" json:"hostname"`
	Address  string `yaml:"address" json:"address"`
	MAC      string `yaml:"mac" json:"mac"`
	VMID     int    `yaml:"vmid,omitempty" json:"vmid,omitempty"`
}

// UserDNSRecord is an operator-owned record in the private namespace. Value
// is an IPv4 address for A records and a private FQDN for CNAME records.
type UserDNSRecord struct {
	Name  string `yaml:"name" json:"name"`
	Type  string `yaml:"type" json:"type"`
	Value string `yaml:"value" json:"value"`
}

// UserFirewallRule is an additive allow exception. A VMID is intentionally
// not persisted: it is only a read-only convenience lookup by the CLI.
type UserFirewallRule struct {
	ID          string   `yaml:"id" json:"id"`
	Source      string   `yaml:"source" json:"source"`
	Destination string   `yaml:"destination" json:"destination"`
	Protocol    string   `yaml:"protocol" json:"protocol"`
	Ports       []string `yaml:"ports,omitempty" json:"ports,omitempty"`
}

// DNSDeletion is runtime reconciliation state for an explicitly removed user
// record. It is intentionally excluded from the canonical model revision.
type DNSDeletion struct {
	Name string `json:"name"`
	Type string `json:"type"`
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
	Module           string                        `json:"module"`
	Artifact         Artifact                      `json:"artifact"`
	Guests           []Component                   `json:"guests,omitempty"`
	Persistent       []PersistentState             `json:"persistent,omitempty"`
	Volumes          []PersistentVolumeDeclaration `json:"volumes,omitempty"`
	Secrets          []SecretDeclaration           `json:"secrets,omitempty"`
	NetworkIntents   []NetworkIntent               `json:"network_intents,omitempty"`
	DNSRecords       []DNSRecord                   `json:"dns_records,omitempty"`
	DHCPReservations []DHCPReservation             `json:"dhcp_reservations,omitempty"`
	Certificates     []CertificateRequest          `json:"certificates,omitempty"`
	Monitoring       []MonitoringDeclaration       `json:"monitoring,omitempty"`
	Backups          []BackupDeclaration           `json:"backups,omitempty"`
	Portal           []PortalEntry                 `json:"portal,omitempty"`
	Security         GuestSecurityDeclaration      `json:"security,omitempty"`
	USBRequirements  []USBRequirement              `json:"usb_requirements,omitempty"`
	AdvertisedRoutes []string                      `json:"advertised_routes,omitempty"`
	ReturnRouting    []string                      `json:"return_routing,omitempty"`
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
	// projection tests. The persisted SiteConfig path is composed by modules;
	// this fixture keeps the projection tests useful without making those
	// components part of NewSite's Core-owned canonical seed.
	for _, component := range []Component{
		{Name: "lab-fw-01", VMID: ProxmoxVMID, Hostname: "lab-fw-01", Zone: "MGMT", Address: "10.10.99.1", Role: "Debian firewall", Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true, Module: "firewall"},
		{Name: "lab-dns-01", VMID: DNS01VMID, Hostname: "lab-dns-01", Zone: "INFRA", Address: "10.10.10.10", Role: "DNS/NTP", DNSAliases: []string{"dns01", "dns"}, Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true, Module: "dns"},
		{Name: "lab-dns-02", VMID: DNS02VMID, Hostname: "lab-dns-02", Zone: "INFRA", Address: "10.10.10.11", Role: "DNS/NTP", DNSAliases: []string{"dns02"}, Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true, Module: "dns"},
		{Name: "lab-monitor-01", VMID: MonitorVMID, Hostname: "lab-monitor-01", Zone: "INFRA", Address: "10.10.10.20", Role: "Pulse monitoring", DNSAliases: []string{"monitor"}, URL: "https://monitor." + DefaultDomain, Monitoring: true, Backup: true, MTLS: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true, Module: "monitoring"},
		{Name: "lab-log-01", VMID: LoggingVMID, Hostname: "lab-log-01", Zone: "INFRA", Address: "10.10.10.40", Role: "Central systemd journal", DNSAliases: []string{"logs"}, Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true, Module: "logging"},
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
		Gateway:                Gateway{Mode: gatewayMode, Upstream: GatewayUpstream{Mode: "dhcp", MAC: DefaultGatewayUpstreamMAC}},
		LogicalProxmoxIdentity: LogicalProxmoxIdentity,
		TestedVersions: TestedVersions{
			Gateway: QualifiedGatewayImage,
			Pulse:   PulseVersion,
		},
		Network: Network{
			Domain: DefaultDomain,
			Zones: []Zone{
				{Name: "TRANSIT", Type: ZoneTypeTransit, VLAN: TransitVLAN, Network: TransitNetwork, Gateway: TransitGateway, AddressMode: "none"},
				{Name: "INFRA", Type: ZoneTypeInfrastructure, VLAN: InfraVLAN, Network: InfraNetwork, Gateway: InfraGateway, AddressMode: "static", DNSAddresses: []string{"10.10.10.10", "10.10.10.11"}, NTPAddresses: []string{"10.10.10.10", "10.10.10.11"}},
				{Name: "SERVERS", Type: ZoneTypeServers, VLAN: 20, Network: "10.10.20.0/24", Gateway: "10.10.20.1", AddressMode: "reservations-only", DNSAddresses: []string{"10.10.10.10", "10.10.10.11"}, NTPAddresses: []string{"10.10.10.10", "10.10.10.11"}},
				{Name: "TRUSTED", Type: ZoneTypeTrusted, VLAN: 30, Network: "10.10.30.0/24", Gateway: "10.10.30.1", AddressMode: "dynamic-reservations", DNSAddresses: []string{"10.10.10.10", "10.10.10.11"}, NTPAddresses: []string{"10.10.10.10", "10.10.10.11"}},
				{Name: "SANDBOX", Type: ZoneTypeSandbox, VLAN: 40, Network: "10.10.40.0/24", Gateway: "10.10.40.1", AddressMode: "dynamic", DNSAddresses: []string{"10.10.40.1"}, NTPAddresses: []string{"10.10.40.1"}},
				{Name: "MGMT", Type: ZoneTypeManagement, VLAN: 99, Network: "10.10.99.0/24", Gateway: "10.10.99.1", AddressMode: "static", DNSAddresses: []string{"10.10.10.10", "10.10.10.11"}, NTPAddresses: []string{"10.10.10.10", "10.10.10.11"}},
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
			{Name: "lab-proxmox-01", Hostname: "lab-proxmox-01", Zone: "MGMT", Address: ProxmoxManagementAddress, Role: "Proxmox host", Tags: []string{TagBoetticher, TagManaged, TagPlatform, TagInfra, TagNetwork, TagMonitoringAgent}, URL: "https://proxmox." + DefaultDomain + ":8006", Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: false, ProductOwned: true, SSHUser: DefaultAdminSSHUser, SSHPort: 22, Logging: true},
			{Name: "lab-portal-01", VMID: PortalVMID, Hostname: "lab-portal-01", Zone: "INFRA", Address: "10.10.10.30", Role: "Generated platform portal", Tags: []string{TagBoetticher, TagManaged, TagPlatform, TagInfra, TagPortal, TagCorePortal, TagBackup}, URL: "https://portal." + DefaultDomain, DNSAliases: []string{"portal"}, SSHUser: DefaultAdminSSHUser, SSHPort: 22, Monitoring: true, Backup: true, MTLS: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true, Logging: true},
		},
	}
	return site
}

func (s Site) Normalize() Site {
	copySite := s
	copySite.Network.Zones = cloneZones(s.Network.Zones)
	copySite.Gateway.Publish = append([]GatewayPublication(nil), s.Gateway.Publish...)
	copySite.Components = cloneComponents(s.Components)
	copySite.Modules = cloneResolvedModules(s.Modules)
	copySite.ModuleConfig = cloneModuleConfig(s.ModuleConfig)
	copySite.Declarations = cloneModuleDeclarations(s.Declarations)
	copySite.USBExports = append([]USBExportBinding(nil), s.USBExports...)
	copySite.RetainedModules = cloneRetainedModules(s.RetainedModules)
	copySite.DHCPReservations = append([]DHCPReservation(nil), s.DHCPReservations...)
	copySite.DNSRecords = append([]UserDNSRecord(nil), s.DNSRecords...)
	copySite.UserFirewallRules = append([]UserFirewallRule(nil), s.UserFirewallRules...)
	for i := range copySite.UserFirewallRules {
		rule := &copySite.UserFirewallRules[i]
		rule.Source, _ = validateFirewallSelector(rule.Source)
		rule.Destination, _ = validateFirewallSelector(rule.Destination)
		rule.Protocol = strings.ToLower(strings.TrimSpace(rule.Protocol))
		rule.Ports, _ = validateFirewallPorts(rule.Ports, rule.Protocol)
	}
	copySite.PendingDNSDeletions = append([]DNSDeletion(nil), s.PendingDNSDeletions...)
	sort.Slice(copySite.Network.Zones, func(i, j int) bool { return copySite.Network.Zones[i].VLAN < copySite.Network.Zones[j].VLAN })
	sort.Slice(copySite.Components, func(i, j int) bool { return copySite.Components[i].Name < copySite.Components[j].Name })
	sort.Slice(copySite.Modules, func(i, j int) bool { return copySite.Modules[i].Name < copySite.Modules[j].Name })
	sort.Slice(copySite.Declarations, func(i, j int) bool { return copySite.Declarations[i].Module < copySite.Declarations[j].Module })
	sort.Slice(copySite.USBExports, func(i, j int) bool {
		if copySite.USBExports[i].Module != copySite.USBExports[j].Module {
			return copySite.USBExports[i].Module < copySite.USBExports[j].Module
		}
		return copySite.USBExports[i].Requirement < copySite.USBExports[j].Requirement
	})
	sort.Slice(copySite.RetainedModules, func(i, j int) bool { return copySite.RetainedModules[i].Module < copySite.RetainedModules[j].Module })
	sort.Slice(copySite.DHCPReservations, func(i, j int) bool {
		if copySite.DHCPReservations[i].Hostname != copySite.DHCPReservations[j].Hostname {
			return copySite.DHCPReservations[i].Hostname < copySite.DHCPReservations[j].Hostname
		}
		return copySite.DHCPReservations[i].MAC < copySite.DHCPReservations[j].MAC
	})
	sort.Slice(copySite.DNSRecords, func(i, j int) bool {
		if copySite.DNSRecords[i].Name != copySite.DNSRecords[j].Name {
			return copySite.DNSRecords[i].Name < copySite.DNSRecords[j].Name
		}
		return copySite.DNSRecords[i].Type < copySite.DNSRecords[j].Type
	})
	sort.Slice(copySite.UserFirewallRules, func(i, j int) bool { return copySite.UserFirewallRules[i].ID < copySite.UserFirewallRules[j].ID })
	sort.Slice(copySite.Gateway.Publish, func(i, j int) bool {
		return copySite.Gateway.Publish[i].Service < copySite.Gateway.Publish[j].Service
	})
	sort.Slice(copySite.PendingDNSDeletions, func(i, j int) bool {
		if copySite.PendingDNSDeletions[i].Name != copySite.PendingDNSDeletions[j].Name {
			return copySite.PendingDNSDeletions[i].Name < copySite.PendingDNSDeletions[j].Name
		}
		return copySite.PendingDNSDeletions[i].Type < copySite.PendingDNSDeletions[j].Type
	})
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
		sort.Slice(copySite.Declarations[i].DHCPReservations, func(a, b int) bool {
			return copySite.Declarations[i].DHCPReservations[a].Hostname < copySite.Declarations[i].DHCPReservations[b].Hostname
		})
	}
	return copySite
}

func cloneZones(input []Zone) []Zone {
	output := append([]Zone(nil), input...)
	for i := range output {
		output[i].DNSAddresses = append([]string(nil), input[i].DNSAddresses...)
		output[i].NTPAddresses = append([]string(nil), input[i].NTPAddresses...)
	}
	return output
}

func cloneComponents(input []Component) []Component {
	output := append([]Component(nil), input...)
	for i := range output {
		output[i].DNSAliases = append([]string(nil), input[i].DNSAliases...)
		output[i].Tags = append([]string(nil), input[i].Tags...)
	}
	return output
}

func cloneResolvedModules(input []ResolvedModule) []ResolvedModule {
	output := append([]ResolvedModule(nil), input...)
	for i := range output {
		output[i].DependsOn = append([]string(nil), input[i].DependsOn...)
		output[i].Requires = append([]string(nil), input[i].Requires...)
		output[i].Provides = append([]string(nil), input[i].Provides...)
	}
	return output
}

func cloneModuleDeclarations(input []ModuleDeclaration) []ModuleDeclaration {
	output := append([]ModuleDeclaration(nil), input...)
	for i := range output {
		declaration := &output[i]
		declaration.Guests = cloneComponents(input[i].Guests)
		declaration.Persistent = append([]PersistentState(nil), input[i].Persistent...)
		declaration.Volumes = append([]PersistentVolumeDeclaration(nil), input[i].Volumes...)
		declaration.Secrets = append([]SecretDeclaration(nil), input[i].Secrets...)
		declaration.NetworkIntents = append([]NetworkIntent(nil), input[i].NetworkIntents...)
		for j := range declaration.NetworkIntents {
			declaration.NetworkIntents[j].Ports = append([]string(nil), input[i].NetworkIntents[j].Ports...)
		}
		declaration.DNSRecords = append([]DNSRecord(nil), input[i].DNSRecords...)
		declaration.DHCPReservations = append([]DHCPReservation(nil), input[i].DHCPReservations...)
		declaration.Certificates = append([]CertificateRequest(nil), input[i].Certificates...)
		for j := range declaration.Certificates {
			declaration.Certificates[j].SANs = append([]string(nil), input[i].Certificates[j].SANs...)
		}
		declaration.Monitoring = append([]MonitoringDeclaration(nil), input[i].Monitoring...)
		for j := range declaration.Monitoring {
			declaration.Monitoring[j].Checks = append([]string(nil), input[i].Monitoring[j].Checks...)
		}
		declaration.Backups = append([]BackupDeclaration(nil), input[i].Backups...)
		declaration.Portal = append([]PortalEntry(nil), input[i].Portal...)
		for j := range declaration.Portal {
			declaration.Portal[j].URLs = append([]string(nil), input[i].Portal[j].URLs...)
			declaration.Portal[j].Docs = append([]string(nil), input[i].Portal[j].Docs...)
		}
		declaration.Security.Devices = append([]DeviceRequirement(nil), input[i].Security.Devices...)
		declaration.Security.Capabilities = append([]string(nil), input[i].Security.Capabilities...)
		declaration.USBRequirements = append([]USBRequirement(nil), input[i].USBRequirements...)
		for j := range declaration.USBRequirements {
			declaration.USBRequirements[j].AllowedIdentities = append([]USBIdentity(nil), input[i].USBRequirements[j].AllowedIdentities...)
		}
		declaration.AdvertisedRoutes = append([]string(nil), input[i].AdvertisedRoutes...)
		declaration.ReturnRouting = append([]string(nil), input[i].ReturnRouting...)
	}
	return output
}

func cloneRetainedModules(input []RetainedModule) []RetainedModule {
	output := append([]RetainedModule(nil), input...)
	for i := range output {
		output[i].Guests = cloneComponents(input[i].Guests)
		output[i].Persistent = append([]PersistentState(nil), input[i].Persistent...)
	}
	return output
}

func (s Site) validateUSBExports() error {
	type key struct{ module, requirement string }
	requirements := map[key]USBRequirement{}
	enabled := map[string]bool{}
	for _, module := range s.Modules {
		enabled[module.Name] = module.Enabled
	}
	for _, declaration := range s.Declarations {
		for _, requirement := range declaration.USBRequirements {
			k := key{declaration.Module, requirement.Name}
			if requirement.Name == "" || requirement.Guest == "" || (requirement.DeviceType != "raw-usb" && requirement.DeviceType != "serial") || requirement.Access != "rw" || len(requirement.AllowedIdentities) == 0 {
				return fmt.Errorf("module %s has invalid USB requirement %q", declaration.Module, requirement.Name)
			}
			if _, exists := requirements[k]; exists {
				return fmt.Errorf("module %s has duplicate USB requirement %q", declaration.Module, requirement.Name)
			}
			requirements[k] = requirement
		}
	}
	ports, bindings, serialIdentities := map[string]bool{}, map[key]bool{}, map[string]bool{}
	for _, binding := range s.USBExports {
		k := key{binding.Module, binding.Requirement}
		requirement, activeRequirement := requirements[k]
		if !usbPortPattern.MatchString(binding.Port) {
			return fmt.Errorf("usb_exports binding %s/%s has invalid physical port %q", binding.Module, binding.Requirement, binding.Port)
		}
		if binding.VendorID != strings.ToLower(binding.VendorID) || binding.ProductID != strings.ToLower(binding.ProductID) || !usbIDPattern.MatchString(binding.VendorID) || !usbIDPattern.MatchString(binding.ProductID) {
			return fmt.Errorf("usb_exports binding %s/%s requires four-digit lowercase vendor_id and product_id", binding.Module, binding.Requirement)
		}
		if activeRequirement {
			allowed := false
			for _, identity := range requirement.AllowedIdentities {
				if identity.VendorID == binding.VendorID && identity.ProductID == binding.ProductID {
					allowed = true
				}
			}
			if !allowed {
				return fmt.Errorf("usb_exports identity %s:%s is not allowed for %s/%s", binding.VendorID, binding.ProductID, binding.Module, binding.Requirement)
			}
		}
		if strings.ContainsAny(binding.Serial, "\r\n\x00") {
			return fmt.Errorf("usb_exports binding %s/%s has invalid serial", binding.Module, binding.Requirement)
		}
		if binding.Serial != "" {
			identity := binding.VendorID + ":" + binding.ProductID + ":" + binding.Serial
			if serialIdentities[identity] {
				return fmt.Errorf("usb_exports contains duplicate physical identity %s", identity)
			}
			serialIdentities[identity] = true
		}
		if ports[binding.Port] {
			return fmt.Errorf("usb_exports contains duplicate physical port %q", binding.Port)
		}
		if bindings[k] {
			return fmt.Errorf("usb_exports contains duplicate binding %s/%s", binding.Module, binding.Requirement)
		}
		ports[binding.Port], bindings[k] = true, true
	}
	for k, requirement := range requirements {
		if enabled[k.module] && requirement.Required && !bindings[k] {
			return fmt.Errorf("modules.%s requires usb_exports binding %s/%s", k.module, k.module, k.requirement)
		}
	}
	return nil
}

func (s Site) Validate() error {
	if s.APIVersion != APIVersion || s.SchemaVersion != SchemaVersion {
		return fmt.Errorf("site schema %q/%d is not supported by boetticher v0.4; recreate the site with boetticher init", s.APIVersion, s.SchemaVersion)
	}
	if s.PlatformVersion == "" {
		return errors.New("platform_version is required")
	}
	if strings.IndexFunc(s.SSHIdentityFile, unicode.IsControl) >= 0 {
		return errors.New("ssh_identity_file contains control characters")
	}
	if s.BootstrapAddress != "" {
		if strings.TrimSpace(s.BootstrapAddress) != s.BootstrapAddress {
			return errors.New("bootstrap_address must not contain surrounding whitespace")
		}
		ip := net.ParseIP(s.BootstrapAddress)
		if ip == nil || ip.To4() == nil || ip.To4().String() != s.BootstrapAddress {
			return fmt.Errorf("bootstrap_address must be a canonical IPv4 address")
		}
	}
	if s.StorageProfile != "single-disk" && s.StorageProfile != "dedicated-data-disk" {
		return fmt.Errorf("unsupported storage_profile %q", s.StorageProfile)
	}
	if s.StorageProfile == "dedicated-data-disk" {
		if err := ValidateStableDevice(s.StorageDevice); err != nil {
			return err
		}
	} else if s.StorageDevice != "" {
		return errors.New("storage_device is only valid for dedicated-data-disk")
	}
	if s.Gateway.Mode != GatewayModeManaged && s.Gateway.Mode != GatewayModeExternal {
		return fmt.Errorf("gateway.mode must be managed or external")
	}
	if err := validateGatewayConfiguration(s); err != nil {
		return err
	}
	if s.Network.Domain != DefaultDomain {
		return fmt.Errorf("network.domain must be %s", DefaultDomain)
	}
	if s.TestedVersions.Gateway != QualifiedGatewayImage {
		return fmt.Errorf("tested_versions.gateway must equal the qualified image %q", QualifiedGatewayImage)
	}
	if s.TestedVersions.Pulse != PulseVersion {
		return fmt.Errorf("tested_versions.pulse must be %q", PulseVersion)
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
	if bifrost, ok := s.ModuleConfig["bifrost"]; ok && (bifrost.Enabled != nil && *bifrost.Enabled || len(bifrost.Upstreams) > 0 || len(bifrost.Models) > 0) {
		if err := ValidateBifrostConfig(bifrost); err != nil {
			return err
		}
	}
	if err := s.validateUSBExports(); err != nil {
		return err
	}
	expectedZones := map[string]struct {
		typ     ZoneType
		vlan    int
		network string
		gateway string
	}{
		"TRANSIT": {typ: ZoneTypeTransit, vlan: TransitVLAN, network: TransitNetwork, gateway: TransitGateway},
		"INFRA":   {typ: ZoneTypeInfrastructure, vlan: InfraVLAN, network: InfraNetwork, gateway: InfraGateway},
		"SERVERS": {typ: ZoneTypeServers, vlan: 20, network: "10.10.20.0/24", gateway: "10.10.20.1"},
		"TRUSTED": {typ: ZoneTypeTrusted, vlan: 30, network: "10.10.30.0/24", gateway: "10.10.30.1"},
		"SANDBOX": {typ: ZoneTypeSandbox, vlan: 40, network: "10.10.40.0/24", gateway: "10.10.40.1"},
		"MGMT":    {typ: ZoneTypeManagement, vlan: 99, network: "10.10.99.0/24", gateway: "10.10.99.1"},
	}
	seenZones := map[string]bool{}
	seenVLANs := map[int]string{}
	for _, z := range s.Network.Zones {
		if seenZones[z.Name] {
			return fmt.Errorf("duplicate zone %q", z.Name)
		}
		seenZones[z.Name] = true
		if previous, exists := seenVLANs[z.VLAN]; exists {
			return fmt.Errorf("zones %s and %s share VLAN %d", previous, z.Name, z.VLAN)
		}
		seenVLANs[z.VLAN] = z.Name
		expected, ok := expectedZones[z.Name]
		if !ok {
			return fmt.Errorf("zone %s does not match the fixed 0.4 network contract", z.Name)
		}
		if !validZoneType(z.Type) {
			return fmt.Errorf("zone %s has unknown semantic type %q", z.Name, z.Type)
		}
		if z.Type != expected.typ || z.VLAN != expected.vlan || z.Network != expected.network || z.Gateway != expected.gateway {
			return fmt.Errorf("zone %s does not match the fixed 0.4 network contract", z.Name)
		}
		if _, _, err := net.ParseCIDR(z.Network); err != nil {
			return fmt.Errorf("zone %s has invalid network: %w", z.Name, err)
		}
		switch z.Type {
		case ZoneTypeTransit:
			if z.AddressMode != "none" || len(z.DNSAddresses) != 0 || len(z.NTPAddresses) != 0 {
				return errors.New("TRANSIT must not provide DHCP, DNS, or NTP services")
			}
		case ZoneTypeTrusted:
			if z.AddressMode != "dynamic-reservations" {
				return errors.New("TRUSTED must provide DHCP reservations")
			}
		case ZoneTypeSandbox:
			if z.AddressMode != "dynamic" {
				return errors.New("SANDBOX must provide dynamic DHCP")
			}
		case ZoneTypeServers:
			if z.AddressMode != "reservations-only" {
				return errors.New("SERVERS must provide reservation-only DHCP")
			}
		case ZoneTypeInfrastructure, ZoneTypeManagement:
			if z.AddressMode != "static" {
				return fmt.Errorf("%s must use static assignments only", z.Name)
			}
		}
	}
	seenComponents := map[string]bool{}
	seenVMIDs := map[int]string{}
	for _, m := range s.Components {
		if err := m.Validate(); err != nil {
			return err
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
	for _, retained := range s.RetainedModules {
		if retained.Module == "" || ModuleOwnershipTag(retained.Module) == "" {
			return fmt.Errorf("retained module has invalid name %q", retained.Module)
		}
		if retained.Disposition != "retained" || retained.Active {
			return fmt.Errorf("retained module %s has invalid inactive disposition", retained.Module)
		}
		ownerTag := ModuleOwnershipTag(retained.Module)
		for _, guest := range retained.Guests {
			if err := guest.Validate(); err != nil {
				return fmt.Errorf("retained module %s contains invalid guest: %w", retained.Module, err)
			}
			if !guest.ProductOwned || !guest.SSHManaged || guest.Module != retained.Module {
				return fmt.Errorf("retained guest %s must remain a product-owned SSH-managed %s guest", guest.Name, retained.Module)
			}
			if guest.VMID < PlatformGuestIDMin || guest.VMID > ModuleGuestIDMax {
				return fmt.Errorf("retained guest %s uses VMID %d outside the boetticher-owned range", guest.Name, guest.VMID)
			}
			hasOwnerTag := false
			for _, tag := range guest.Tags {
				if tag == ownerTag {
					hasOwnerTag = true
					break
				}
			}
			if !hasOwnerTag {
				return fmt.Errorf("retained guest %s is missing canonical ownership tag %q", guest.Name, ownerTag)
			}
			if seenComponents[guest.Name] {
				return fmt.Errorf("retained guest %q duplicates a platform component", guest.Name)
			}
			seenComponents[guest.Name] = true
			if previous, exists := seenVMIDs[guest.VMID]; exists {
				return fmt.Errorf("retained guest %s and %s share VMID %d", previous, guest.Name, guest.VMID)
			}
			seenVMIDs[guest.VMID] = guest.Name
		}
	}
	if len(seenZones) != len(expectedZones) {
		return fmt.Errorf("0.4 requires exactly TRANSIT, INFRA, SERVERS, TRUSTED, SANDBOX, and MGMT zones")
	}
	if err := validateDHCPReservations(s); err != nil {
		return err
	}
	if err := validateUserDNSRecords(s); err != nil {
		return err
	}
	if err := validateUserFirewallRules(s); err != nil {
		return err
	}
	requiredComponents := map[string]struct {
		address string
		vmid    int
	}{
		"lab-proxmox-01": {address: ProxmoxManagementAddress, vmid: 0},
		"lab-portal-01":  {address: "10.10.10.30", vmid: PortalVMID},
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
		}{address: "10.10.10.10", vmid: DNS01VMID}
		requiredComponents["lab-dns-02"] = struct {
			address string
			vmid    int
		}{address: "10.10.10.11", vmid: DNS02VMID}
	}
	if composed && resolvedModuleEnabled(s.Modules, "monitoring", true) {
		requiredComponents["lab-monitor-01"] = struct {
			address string
			vmid    int
		}{address: "10.10.10.20", vmid: MonitorVMID}
	}
	if composed && resolvedModuleEnabled(s.Modules, "logging", true) {
		requiredComponents["lab-log-01"] = struct {
			address string
			vmid    int
		}{address: "10.10.10.40", vmid: LoggingVMID}
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

// Validate checks component fields that are safe to reuse in projections,
// diagnostics, and remote command arguments. Site.Validate adds collection-
// level ownership, address, VMID, and collision checks.
func (m Component) Validate() error {
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
	return nil
}

func validateGatewayConfiguration(s Site) error {
	if s.Gateway.Upstream.Mode != "dhcp" {
		return fmt.Errorf("gateway.upstream.mode must be dhcp")
	}
	if err := ValidateGatewayUpstreamMAC(s.Gateway.Upstream.MAC); err != nil {
		return err
	}
	if s.Gateway.Mode == GatewayModeExternal && len(s.Gateway.Publish) > 0 {
		return errors.New("gateway.publish requires managed gateway mode")
	}
	seen := map[string]struct{}{}
	for _, publication := range s.Gateway.Publish {
		if publication.Service != "dns" {
			return fmt.Errorf("gateway.publish.service %q is not supported; only dns is available", publication.Service)
		}
		if _, exists := seen[publication.Service]; exists {
			return fmt.Errorf("gateway.publish contains duplicate service %q", publication.Service)
		}
		seen[publication.Service] = struct{}{}
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
		for _, intent := range declaration.NetworkIntents {
			if err := validateNetworkIntent(intent); err != nil {
				return fmt.Errorf("module %s network intent: %w", declaration.Module, err)
			}
		}
		for _, route := range declaration.AdvertisedRoutes {
			if _, network, err := net.ParseCIDR(route); err != nil || network.String() != route {
				return fmt.Errorf("module %s has invalid advertised route %q", declaration.Module, route)
			}
		}
		for _, secret := range declaration.Secrets {
			if !modelTokenPattern.MatchString(secret.Name) || secret.Purpose == "" || secret.Consumer == "" || secret.Delivery == "" || strings.ContainsAny(secret.Purpose+secret.Consumer+secret.Delivery, "\r\n") {
				return fmt.Errorf("module %s has invalid secret declaration %q", declaration.Module, secret.Name)
			}
			if secret.Lifecycle != "" && secret.Lifecycle != SecretLifecycleRuntime && secret.Lifecycle != SecretLifecycleBootstrap {
				return fmt.Errorf("module %s secret %s has unsupported lifecycle %q", declaration.Module, secret.Name, secret.Lifecycle)
			}
		}
		if !declaration.Security.Unprivileged && len(declaration.Security.Devices) != 0 {
			return fmt.Errorf("module %s declares devices without an unprivileged security contract", declaration.Module)
		}
		if len(declaration.Security.Capabilities) != 0 {
			return fmt.Errorf("module %s requests unrelated Linux capabilities", declaration.Module)
		}
		if declaration.Security.Unprivileged {
			deviceNames := map[string]bool{}
			for _, device := range declaration.Security.Devices {
				if device.Path == "" || device.Type == "" || device.Major < 0 || device.Minor < 0 || device.Access == "" {
					return fmt.Errorf("module %s has an incomplete device requirement", declaration.Module)
				}
				if strings.ContainsAny(device.Path, "\r\n '") || device.Type != "c" || device.Access != "rwm" {
					return fmt.Errorf("module %s has an unsafe device requirement for %s", declaration.Module, device.Path)
				}
				if device.Name != "" {
					if !modelTokenPattern.MatchString(device.Name) || deviceNames[device.Name] {
						return fmt.Errorf("module %s has invalid or duplicate device slot name %q", declaration.Module, device.Name)
					}
					deviceNames[device.Name] = true
				}
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

var dnsLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func validateDHCPReservations(s Site) error {
	servers, ok := zoneByName(s, "SERVERS")
	if !ok {
		return errors.New("SERVERS zone is required before validating DHCP reservations")
	}
	seenHostnames := map[string]struct{}{}
	seenAddresses := map[string]struct{}{}
	seenMACs := map[string]struct{}{}
	platformAddresses := map[string]struct{}{}
	for _, component := range s.PlatformComponents() {
		if address := net.ParseIP(component.Address).To4(); address != nil {
			platformAddresses[address.String()] = struct{}{}
		}
	}
	for _, reservation := range s.DHCPReservations {
		if reservation.Zone != "SERVERS" {
			return fmt.Errorf("DHCP reservation %q must use the fixed SERVERS zone", reservation.Hostname)
		}
		if !IsDNSLabel(reservation.Hostname) {
			return fmt.Errorf("DHCP reservation hostname %q must be one DNS label", reservation.Hostname)
		}
		address := net.ParseIP(reservation.Address)
		if address == nil || address.To4() == nil || !usableIPInZone(address, servers) || address.To4().String() == servers.Gateway {
			return fmt.Errorf("DHCP reservation %s address %q is outside usable SERVERS addresses", reservation.Hostname, reservation.Address)
		}
		canonicalAddress := address.To4().String()
		if _, exists := platformAddresses[canonicalAddress]; exists {
			ownedMatch := false
			for _, component := range s.PlatformComponents() {
				if component.ProductOwned && component.Module != "" && component.Address == canonicalAddress && component.Hostname == reservation.Hostname && strings.EqualFold(component.MAC, reservation.MAC) {
					ownedMatch = true
					break
				}
			}
			if !ownedMatch {
				return fmt.Errorf("DHCP reservation %s address %s collides with an existing platform address", reservation.Hostname, canonicalAddress)
			}
		}
		if _, exists := seenAddresses[canonicalAddress]; exists {
			return fmt.Errorf("duplicate DHCP reservation address %s", canonicalAddress)
		}
		seenAddresses[canonicalAddress] = struct{}{}
		parsedMAC, err := net.ParseMAC(reservation.MAC)
		if err != nil || len(parsedMAC) != 6 {
			return fmt.Errorf("DHCP reservation %s has invalid Ethernet MAC %q", reservation.Hostname, reservation.MAC)
		}
		canonicalMAC := strings.ToLower(parsedMAC.String())
		if _, exists := seenHostnames[strings.ToLower(reservation.Hostname)]; exists {
			return fmt.Errorf("duplicate DHCP reservation hostname %q", reservation.Hostname)
		}
		if _, exists := seenMACs[canonicalMAC]; exists {
			return fmt.Errorf("duplicate DHCP reservation MAC %q", reservation.MAC)
		}
		seenHostnames[strings.ToLower(reservation.Hostname)] = struct{}{}
		seenMACs[canonicalMAC] = struct{}{}
		if reservation.VMID != 0 && (reservation.VMID < UserGuestIDMin || reservation.VMID > UserGuestIDMax) {
			ownedMatch := false
			for _, component := range s.PlatformComponents() {
				if component.ProductOwned && component.Module != "" && component.VMID == reservation.VMID && component.Hostname == reservation.Hostname && component.Address == canonicalAddress && strings.EqualFold(component.MAC, reservation.MAC) {
					ownedMatch = true
					break
				}
			}
			if !ownedMatch {
				return fmt.Errorf("DHCP reservation %s uses VMID %d outside the user-workload range", reservation.Hostname, reservation.VMID)
			}
		}
	}
	return nil
}

func validateUserDNSRecords(s Site) error {
	domain := strings.ToLower(strings.TrimSuffix(s.Network.Domain, "."))
	owned := map[string]struct{}{}
	for _, component := range s.PlatformComponents() {
		owned[strings.ToLower(component.Hostname+"."+domain)] = struct{}{}
		for _, alias := range component.DNSAliases {
			owned[strings.ToLower(strings.TrimSuffix(alias, ".")+"."+domain)] = struct{}{}
		}
		if component.URL != "" {
			parsed, err := url.Parse(component.URL)
			if err == nil && strings.HasSuffix(strings.ToLower(parsed.Hostname()), "."+domain) {
				owned[strings.ToLower(parsed.Hostname())] = struct{}{}
			}
		}
	}
	for _, declaration := range s.Declarations {
		for _, record := range declaration.DNSRecords {
			owned[strings.ToLower(strings.TrimSuffix(record.Name, "."))] = struct{}{}
		}
	}
	managedZones := make([]string, 0, 3)
	for _, zone := range s.Network.Zones {
		if zone.Type == ZoneTypeServers || zone.Type == ZoneTypeTrusted || zone.Type == ZoneTypeSandbox {
			managedZones = append(managedZones, strings.ToLower(zone.Name)+"."+domain)
		}
	}
	seen := map[string]struct{}{}
	cnameTargets := map[string]string{}
	for _, record := range s.DNSRecords {
		name, err := privateDNSName(record.Name, domain)
		if err != nil {
			return fmt.Errorf("user DNS record %q: %w", record.Name, err)
		}
		if _, exists := owned[name]; exists {
			return fmt.Errorf("user DNS record %s collides with a Core or module-owned name", name)
		}
		for _, zone := range managedZones {
			if name == zone || strings.HasSuffix(name, "."+zone) {
				return fmt.Errorf("user DNS record %s is inside the DHCP/DDNS-owned namespace %s", name, zone)
			}
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("duplicate user DNS record %q", name)
		}
		seen[name] = struct{}{}
		switch record.Type {
		case "A":
			ip := net.ParseIP(record.Value)
			if ip == nil || ip.To4() == nil || !ipInAnyZone(ip, s.Network.Zones) {
				return fmt.Errorf("user A record %s must contain an address from a fixed internal network", name)
			}
		case "CNAME":
			target, targetErr := privateDNSName(record.Value, domain)
			if targetErr != nil {
				return fmt.Errorf("user CNAME record %s: %w", name, targetErr)
			}
			if target == name {
				return fmt.Errorf("user CNAME record %s cannot target itself", name)
			}
			cnameTargets[name] = target
		default:
			return fmt.Errorf("user DNS record %s has unsupported type %q", name, record.Type)
		}
	}
	for name := range cnameTargets {
		seenPath := map[string]struct{}{}
		for current := name; ; {
			if _, exists := seenPath[current]; exists {
				return fmt.Errorf("user DNS CNAME records contain a cycle at %s", current)
			}
			seenPath[current] = struct{}{}
			next, exists := cnameTargets[current]
			if !exists {
				break
			}
			current = next
		}
	}
	return nil
}

const maxUserFirewallRules = 64

func validateUserFirewallRules(s Site) error {
	if len(s.UserFirewallRules) > maxUserFirewallRules {
		return fmt.Errorf("firewall_rules must contain at most %d rules", maxUserFirewallRules)
	}
	ids, semantics := map[string]struct{}{}, map[string]struct{}{}
	for _, rule := range s.UserFirewallRules {
		if !strings.HasPrefix(rule.ID, "ufr-") || !modelTokenPattern.MatchString(rule.ID) {
			return fmt.Errorf("firewall rule ID %q is not a stable ufr- identifier", rule.ID)
		}
		if _, ok := ids[rule.ID]; ok {
			return fmt.Errorf("duplicate firewall rule ID %q", rule.ID)
		}
		ids[rule.ID] = struct{}{}
		source, err := validateFirewallSelector(rule.Source)
		if err != nil {
			return fmt.Errorf("firewall rule %s source: %w", rule.ID, err)
		}
		destination, err := validateFirewallSelector(rule.Destination)
		if err != nil {
			return fmt.Errorf("firewall rule %s destination: %w", rule.ID, err)
		}
		protocol := strings.ToLower(strings.TrimSpace(rule.Protocol))
		if protocol != "tcp" && protocol != "udp" && protocol != "icmp" {
			return fmt.Errorf("firewall rule %s protocol %q is not tcp, udp, or icmp", rule.ID, rule.Protocol)
		}
		ports, err := validateFirewallPorts(rule.Ports, protocol)
		if err != nil {
			return fmt.Errorf("firewall rule %s: %w", rule.ID, err)
		}
		if (firewallSelectorProtected(s, source) || firewallSelectorProtected(s, destination)) && !IsReservedServersPulseRule(s, source, destination, protocol, ports) {
			return fmt.Errorf("firewall rule %s crosses a protected Core boundary", rule.ID)
		}
		key := source + "|" + destination + "|" + protocol + "|" + strings.Join(ports, ",")
		if _, ok := semantics[key]; ok {
			return fmt.Errorf("firewall rule %s duplicates an equivalent rule", rule.ID)
		}
		semantics[key] = struct{}{}
	}
	return nil
}

func validateFirewallSelector(value string) (string, error) {
	value = strings.ToUpper(strings.TrimSpace(value))
	for _, zone := range []string{"SERVERS", "TRUSTED", "SANDBOX"} {
		if value == zone {
			return value, nil
		}
	}
	ip, network, err := net.ParseCIDR(value)
	if err != nil || ip.To4() == nil || network.IP.To4() == nil || ip.String() != strings.Split(value, "/")[0] {
		return "", fmt.Errorf("%q is not a supported zone or canonical IPv4/CIDR selector", value)
	}
	return network.String(), nil
}

func validateFirewallPorts(values []string, protocol string) ([]string, error) {
	if len(values) > 16 {
		return nil, errors.New("firewall rule may contain at most 16 ports or ranges")
	}
	result, seen := []string{}, map[string]struct{}{}
	for _, raw := range values {
		parts := strings.Split(strings.TrimSpace(raw), "-")
		if len(parts) > 2 || len(parts) == 0 {
			return nil, fmt.Errorf("invalid port range %q", raw)
		}
		start, err := strconv.Atoi(parts[0])
		if err != nil || start < 1 || start > 65535 {
			return nil, fmt.Errorf("invalid port %q", raw)
		}
		end := start
		if len(parts) == 2 {
			end, err = strconv.Atoi(parts[1])
			if err != nil || end < start || end > 65535 {
				return nil, fmt.Errorf("invalid port range %q", raw)
			}
		}
		if end-start+1 > 1024 {
			return nil, fmt.Errorf("port range %q exceeds 1024 ports", raw)
		}
		if protocol == "icmp" {
			return nil, errors.New("ICMP does not accept ports")
		}
		canonical := strconv.Itoa(start)
		if end != start {
			canonical += "-" + strconv.Itoa(end)
		}
		if _, ok := seen[canonical]; ok {
			return nil, fmt.Errorf("duplicate port or range %q", raw)
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical)
	}
	sort.Strings(result)
	return result, nil
}

func firewallSelectorProtected(s Site, selector string) bool {
	selector = strings.ToUpper(strings.TrimSpace(selector))
	for _, zone := range s.Network.Zones {
		if selector != zone.Name {
			continue
		}
		if zone.Type != ZoneTypeServers && zone.Type != ZoneTypeTrusted && zone.Type != ZoneTypeSandbox {
			return true
		}
		_, network, err := net.ParseCIDR(zone.Network)
		if err != nil {
			return true
		}
		for _, component := range s.PlatformComponents() {
			if component.ProductOwned {
				if ip := net.ParseIP(component.Address).To4(); ip != nil && network.Contains(ip) {
					return true
				}
			}
		}
		return false
	}
	_, network, err := net.ParseCIDR(selector)
	if err != nil {
		return false
	}
	for _, component := range s.PlatformComponents() {
		if ip := net.ParseIP(component.Address).To4(); ip != nil && network.Contains(ip) {
			return true
		}
	}
	for _, zone := range s.Network.Zones {
		if zone.Type == ZoneTypeInfrastructure || zone.Type == ZoneTypeManagement || zone.Type == ZoneTypeTransit {
			_, protected, e := net.ParseCIDR(zone.Network)
			if e == nil && (network.Contains(protected.IP) || protected.Contains(network.IP)) {
				return true
			}
		}
	}
	return false
}

// IsReservedServersPulseRule is the one user-workload exception to the Core
// boundary. An external, reservation-backed dashboard may read the fixed
// Pulse HTTPS endpoint, but it cannot widen that access to another Core
// service, port, or an entire zone.
func IsReservedServersPulseRule(s Site, source, destination, protocol string, ports []string) bool {
	if protocol != "tcp" || len(ports) != 1 || ports[0] != "443" {
		return false
	}
	sourceIP, sourceNetwork, err := net.ParseCIDR(source)
	if err != nil || sourceIP.To4() == nil {
		return false
	}
	ones, bits := sourceNetwork.Mask.Size()
	if bits != 32 || ones != 32 {
		return false
	}
	servers, ok := zoneByName(s, "SERVERS")
	if !ok {
		return false
	}
	_, serversNetwork, err := net.ParseCIDR(servers.Network)
	if err != nil || !serversNetwork.Contains(sourceIP) {
		return false
	}
	for _, reservation := range s.DHCPReservations {
		reservationIP := net.ParseIP(reservation.Address).To4()
		if reservation.Zone == "SERVERS" && reservationIP != nil && reservationIP.String() == sourceIP.To4().String() {
			for _, component := range s.PlatformComponents() {
				if component.Name == "lab-monitor-01" && component.Module == "monitoring" && component.Zone == "INFRA" {
					return destination == component.Address+"/32"
				}
			}
		}
	}
	return false
}

func privateDNSName(raw, domain string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if name == "" || name == domain || !strings.HasSuffix(name, "."+domain) {
		return "", fmt.Errorf("name must be inside %s", domain)
	}
	for _, label := range strings.Split(name, ".") {
		if !IsDNSLabel(label) {
			return "", fmt.Errorf("name %q contains an unsafe label", raw)
		}
	}
	return name, nil
}

func zoneByName(s Site, name string) (Zone, bool) {
	for _, zone := range s.Network.Zones {
		if zone.Name == name {
			return zone, true
		}
	}
	return Zone{}, false
}

func ipInZone(ip net.IP, zone Zone) bool {
	_, network, err := net.ParseCIDR(zone.Network)
	return err == nil && network.Contains(ip.To4())
}

func usableIPInZone(ip net.IP, zone Zone) bool {
	_, network, err := net.ParseCIDR(zone.Network)
	if err != nil {
		return false
	}
	candidate := ip.To4()
	networkAddress := network.IP.To4()
	if candidate == nil || networkAddress == nil || !network.Contains(candidate) {
		return false
	}
	broadcast := make(net.IP, net.IPv4len)
	for index := range broadcast {
		broadcast[index] = networkAddress[index] | ^network.Mask[index]
	}
	return !candidate.Equal(networkAddress) && !candidate.Equal(broadcast)
}

func ipInAnyZone(ip net.IP, zones []Zone) bool {
	for _, zone := range zones {
		if ipInZone(ip, zone) {
			return true
		}
	}
	return false
}

func validZoneType(value ZoneType) bool {
	switch value {
	case ZoneTypeTransit, ZoneTypeInfrastructure, ZoneTypeServers, ZoneTypeTrusted, ZoneTypeSandbox, ZoneTypeManagement:
		return true
	default:
		return false
	}
}

func zoneTypeForName(name string) ZoneType {
	switch name {
	case "INFRA":
		return ZoneTypeInfrastructure
	case "TRUSTED":
		return ZoneTypeTrusted
	case "SERVERS":
		return ZoneTypeServers
	case "SANDBOX":
		return ZoneTypeSandbox
	case "MGMT":
		return ZoneTypeManagement
	case "TRANSIT":
		return ZoneTypeTransit
	default:
		return ""
	}
}

// ZoneForType resolves a module's semantic placement request through the
// canonical site network. It never permits a module to select a VLAN or
// interface directly.
func (s Site) ZoneForType(zoneType ZoneType) (Zone, error) {
	if !validZoneType(zoneType) {
		return Zone{}, fmt.Errorf("unknown zone type %q", zoneType)
	}
	for _, zone := range s.Network.Zones {
		if zone.Type == zoneType {
			return zone, nil
		}
	}
	return Zone{}, fmt.Errorf("zone type %q is not configured", zoneType)
}

func validateNetworkIntent(intent NetworkIntent) error {
	if !modelTokenPattern.MatchString(intent.Source) || !modelTokenPattern.MatchString(intent.Destination) {
		return fmt.Errorf("source and destination must be safe references")
	}
	switch intent.Protocol {
	case "tcp", "udp", "tcp/udp", "icmp", "any":
	default:
		return fmt.Errorf("unsupported protocol %q", intent.Protocol)
	}
	switch intent.Direction {
	case "egress", "ingress", "bidirectional":
	default:
		return fmt.Errorf("unsupported direction %q", intent.Direction)
	}
	if intent.Purpose == "" || strings.ContainsAny(intent.Purpose, "\r\n") {
		return errors.New("purpose is required and must not contain newlines")
	}
	if intent.Endpoint != "" {
		parsed, err := url.Parse(intent.Endpoint)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return fmt.Errorf("endpoint must be a valid HTTPS URL")
		}
	}
	for _, port := range intent.Ports {
		if !networkPortPattern.MatchString(port) {
			return fmt.Errorf("unsafe port %q", port)
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
