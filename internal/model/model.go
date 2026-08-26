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
	SchemaVersion       = 1
	PlatformVersion     = "0.1.0"
	OPNsenseSeries      = "26.7"
	QualifiedOPNsense   = "26.7.0"
	ZabbixSeries        = "7.0 LTS"
	DefaultDomain       = "lab.home.arpa"
	DefaultSiteDir      = "my-homelab"
	DefaultAgeIdentity  = "~/.config/labinabox/age/identity.txt"
	DefaultSSHConfig    = "~/.ssh/config.d/labinabox.conf"
	DefaultAdminSSHUser = "labadmin"
	DefaultProxmoxNode  = "lab-proxmox-01"
	ProxmoxVMID         = 100
	DNS01VMID           = 110
	DNS02VMID           = 111
	MonitorVMID         = 120
	PortalVMID          = 130
)

var modelTokenPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,253}$`)

type Site struct {
	APIVersion       string         `json:"api_version"`
	PlatformVersion  string         `json:"platform_version"`
	SchemaVersion    int            `json:"schema_version"`
	StorageProfile   string         `json:"storage_profile"`
	ProxmoxNode      string         `json:"proxmox_node"`
	BootstrapAddress string         `json:"bootstrap_address,omitempty"`
	SSHIdentityFile  string         `json:"ssh_identity_file,omitempty"`
	PhysicalTrunk    string         `json:"physical_trunk,omitempty"`
	TestedVersions   TestedVersions `json:"tested_versions"`
	Network          Network        `json:"network"`
	PKI              PKIMetadata    `json:"pki"`
	SecretMetadata   SecretMetadata `json:"secret_metadata"`
	Modules          []Module       `json:"modules"`
}

type TestedVersions struct {
	OPNsense string `json:"opnsense"`
	Zabbix   string `json:"zabbix"`
}

type Network struct {
	Domain string `json:"domain"`
	Zones  []Zone `json:"zones"`
}

type Zone struct {
	Name         string   `json:"name"`
	VLAN         int      `json:"vlan"`
	Network      string   `json:"network"`
	Gateway      string   `json:"gateway"`
	AddressMode  string   `json:"address_mode"`
	DNSAddresses []string `json:"dns_addresses"`
	NTPAddresses []string `json:"ntp_addresses"`
}

type SecretMetadata struct {
	InstallationID string `json:"installation_id"`
	AgeRecipient   string `json:"age_recipient"`
}

type PKIMetadata struct {
	RootCommonName     string `json:"root_common_name"`
	RootFingerprint    string `json:"root_fingerprint"`
	RootExpiry         string `json:"root_expiry"`
	IssuingCommonName  string `json:"issuing_common_name"`
	IssuingFingerprint string `json:"issuing_fingerprint"`
	IssuingExpiry      string `json:"issuing_expiry"`
}

type Module struct {
	Name         string   `json:"name"`
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
	MTLS         bool     `json:"mtls"`
	SSHManaged   bool     `json:"ssh_managed"`
	JumpAllowed  bool     `json:"jump_allowed"`
	ProductOwned bool     `json:"product_owned"`
}

func NewDefaultSite(installationID, ageRecipient string) Site {
	return Site{
		APIVersion:      "labinabox/v1",
		PlatformVersion: PlatformVersion,
		SchemaVersion:   SchemaVersion,
		StorageProfile:  "single-disk",
		ProxmoxNode:     DefaultProxmoxNode,
		TestedVersions: TestedVersions{
			OPNsense: QualifiedOPNsense,
			Zabbix:   ZabbixSeries,
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
		SecretMetadata: SecretMetadata{InstallationID: installationID, AgeRecipient: ageRecipient},
		Modules: []Module{
			{Name: "lab-proxmox-01", Hostname: "lab-proxmox-01", Zone: "MGMT", Address: "10.10.99.5", Role: "Proxmox host", Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: false, ProductOwned: true, SSHUser: DefaultAdminSSHUser, SSHPort: 22},
			{Name: "lab-fw-01", Hostname: "lab-fw-01", Zone: "MGMT", Address: "10.10.99.1", Role: "OPNsense firewall", URL: "https://opnsense." + DefaultDomain, Monitoring: true, Backup: true, MTLS: false, SSHManaged: false, JumpAllowed: false, ProductOwned: true},
			{Name: "lab-dns-01", Hostname: "lab-dns-01", Zone: "SERVERS", Address: "10.10.20.10", Role: "DNS/NTP", DNSAliases: []string{"dns01", "dns"}, SSHUser: DefaultAdminSSHUser, SSHPort: 22, Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
			{Name: "lab-dns-02", Hostname: "lab-dns-02", Zone: "SERVERS", Address: "10.10.20.11", Role: "DNS/NTP", DNSAliases: []string{"dns02"}, SSHUser: DefaultAdminSSHUser, SSHPort: 22, Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
			{Name: "lab-monitor-01", Hostname: "lab-monitor-01", Zone: "MGMT", Address: "10.10.99.20", Role: "Zabbix", URL: "https://monitor." + DefaultDomain, DNSAliases: []string{"monitor"}, SSHUser: DefaultAdminSSHUser, SSHPort: 22, Monitoring: true, Backup: true, MTLS: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
			{Name: "lab-portal-01", Hostname: "lab-portal-01", Zone: "SERVERS", Address: "10.10.20.30", Role: "Generated platform portal", URL: "https://portal." + DefaultDomain, DNSAliases: []string{"portal"}, SSHUser: DefaultAdminSSHUser, SSHPort: 22, Monitoring: true, Backup: true, MTLS: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
		},
	}
}

func (s Site) Normalize() Site {
	copySite := s
	copySite.Network.Zones = append([]Zone(nil), s.Network.Zones...)
	copySite.Modules = append([]Module(nil), s.Modules...)
	sort.Slice(copySite.Network.Zones, func(i, j int) bool { return copySite.Network.Zones[i].VLAN < copySite.Network.Zones[j].VLAN })
	sort.Slice(copySite.Modules, func(i, j int) bool { return copySite.Modules[i].Name < copySite.Modules[j].Name })
	for i := range copySite.Modules {
		copySite.Modules[i].DNSAliases = append([]string(nil), copySite.Modules[i].DNSAliases...)
		sort.Strings(copySite.Modules[i].DNSAliases)
	}
	return copySite
}

func (s Site) Validate() error {
	if s.APIVersion != "labinabox/v1" || s.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported site schema %q/%d", s.APIVersion, s.SchemaVersion)
	}
	if s.PlatformVersion == "" {
		return errors.New("platform_version is required")
	}
	if s.StorageProfile != "single-disk" && s.StorageProfile != "dedicated-data-disk" {
		return fmt.Errorf("unsupported storage_profile %q", s.StorageProfile)
	}
	if s.ProxmoxNode != DefaultProxmoxNode {
		return fmt.Errorf("proxmox_node must be %q in V1", DefaultProxmoxNode)
	}
	if s.Network.Domain != DefaultDomain {
		return fmt.Errorf("network.domain must be %s", DefaultDomain)
	}
	if s.TestedVersions.OPNsense != QualifiedOPNsense {
		return fmt.Errorf("tested_versions.opnsense must equal the explicitly qualified %s patch; newer patches require qualification", QualifiedOPNsense)
	}
	if s.TestedVersions.Zabbix != ZabbixSeries {
		return fmt.Errorf("tested_versions.zabbix must be %q", ZabbixSeries)
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
	seenModules := map[string]bool{}
	for _, m := range s.Modules {
		if m.Name == "" || m.Hostname == "" || m.Address == "" || m.Zone == "" {
			return fmt.Errorf("module %q is missing name, hostname, zone, or address", m.Name)
		}
		for field, value := range map[string]string{"name": m.Name, "hostname": m.Hostname, "zone": m.Zone, "ssh_user": m.SSHUser} {
			if value != "" && !modelTokenPattern.MatchString(value) {
				return fmt.Errorf("module %s has unsafe %s", m.Name, field)
			}
		}
		for _, alias := range m.DNSAliases {
			if !modelTokenPattern.MatchString(alias) {
				return fmt.Errorf("module %s has unsafe DNS alias %q", m.Name, alias)
			}
		}
		if strings.ContainsAny(m.Role+m.URL, "\r\n") {
			return fmt.Errorf("module %s contains a newline in generated metadata", m.Name)
		}
		if seenModules[m.Name] {
			return fmt.Errorf("duplicate module %q", m.Name)
		}
		seenModules[m.Name] = true
		if ip := net.ParseIP(m.Address); ip == nil || ip.To4() == nil {
			return fmt.Errorf("module %s has invalid IPv4 address %q", m.Name, m.Address)
		}
		if !seenZones[m.Zone] {
			return fmt.Errorf("module %s references unknown zone %q", m.Name, m.Zone)
		}
	}
	if len(seenZones) != len(expectedZones) {
		return fmt.Errorf("V1 requires exactly TRUSTED, SERVERS, SANDBOX, and MGMT zones")
	}
	requiredModules := map[string]string{
		"lab-proxmox-01": "10.10.99.5",
		"lab-fw-01":      "10.10.99.1",
		"lab-dns-01":     "10.10.20.10",
		"lab-dns-02":     "10.10.20.11",
		"lab-monitor-01": "10.10.99.20",
		"lab-portal-01":  "10.10.20.30",
	}
	for required, address := range requiredModules {
		found, ok := seenModules[required]
		if !ok || !found {
			return fmt.Errorf("required foundation module %q is missing", required)
		}
		for _, m := range s.Modules {
			if m.Name == required && m.Address != address {
				return fmt.Errorf("foundation module %s must use %s", required, address)
			}
		}
	}
	return nil
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
