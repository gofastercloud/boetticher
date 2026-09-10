// Package clientservices contains the small shared DHCP/DNS/NTP intent model
// used by the firewall appliance. It owns no provider transport or CLI
// grammar; those remain consumers of this typed configuration.
package clientservices

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/gofastercloud/boetticher/internal/bifrost"
	"github.com/gofastercloud/boetticher/internal/model"
)

const (
	LeaseDuration12Hours  = "12h"
	ScopeReservationsOnly = "reservations-only"
	ScopePool             = "pool"
	DNSResolverPort       = 853
	StubbyListenAddress   = "127.0.0.1#5453"
	LeaseFilePath         = "/etc/boetticher/dhcp.leases"
	ProbeAddressStart     = 250
	ProbeAddressEnd       = 254
)

// MediaReferenceConfig contains the installation's reference values. These
// values seed omitted operator fields; validation accepts any safe equivalent.
type MediaReferenceConfig struct {
	ApplicationDomain string
	Aliases           MediaAliases
}

type MediaAliases struct {
	Radarr   string `yaml:"radarr,omitempty" json:"radarr,omitempty"`
	Sonarr   string `yaml:"sonarr,omitempty" json:"sonarr,omitempty"`
	Bazarr   string `yaml:"bazarr,omitempty" json:"bazarr,omitempty"`
	Prowlarr string `yaml:"prowlarr,omitempty" json:"prowlarr,omitempty"`
	Trailarr string `yaml:"trailarr,omitempty" json:"trailarr,omitempty"`
}

var DefaultMediaReference = MediaReferenceConfig{
	// Site-specific values are supplied by the operator/reference example;
	// validation must never require a personal domain or aliases.
}

// Modules is the installed lab.yml service intent. A nil capability block is
// deliberately different from a disabled block: read-only commands report
// nil as not configured and approved apply operations may materialise defaults.
type Modules struct {
	Systems       []System             `yaml:"systems,omitempty" json:"systems,omitempty"`
	Tailnet       *TailnetConfig       `yaml:"tailnet,omitempty" json:"tailnet,omitempty"`
	DNS           *DNSConfig           `yaml:"dns,omitempty" json:"dns,omitempty"`
	DHCP          *DHCPConfig          `yaml:"dhcp,omitempty" json:"dhcp,omitempty"`
	VPN           *VPNConfig           `yaml:"vpn,omitempty" json:"vpn,omitempty"`
	Observability *ObservabilityConfig `yaml:"observability,omitempty" json:"observability,omitempty"`
	Media         *MediaConfig         `yaml:"media,omitempty" json:"media,omitempty"`
	// Arrstack is source compatibility for internal tests and older callers;
	// it is never persisted or advertised in the public configuration.
	Arrstack *ArrstackConfig `yaml:"-" json:"-"`
}

// System registers an existing user-owned Proxmox guest. Boetticher projects
// only its narrow network policy; the guest lifecycle stays with Proxmox.
type System struct {
	Name       string `yaml:"name" json:"name"`
	VMID       int    `yaml:"vmid" json:"vmid"`
	Kind       string `yaml:"kind" json:"kind"`
	GuestName  string `yaml:"guest_name" json:"guest_name"`
	MAC        string `yaml:"mac" json:"mac"`
	Address    string `yaml:"address" json:"address"`
	Port       int    `yaml:"port" json:"port"`
	Monitoring bool   `yaml:"monitoring,omitempty" json:"monitoring,omitempty"`
}

// SystemsExpanded derives DHCP reservations from canonical system intent.
func SystemsExpanded(modules Modules) Modules {
	result := modules.Clone()
	if result.DHCP == nil {
		return result
	}
	for _, system := range result.Systems {
		result.DHCP.Reservations = append(result.DHCP.Reservations, Reservation{Name: strings.ToLower(system.Name), Zone: "SERVERS", MAC: system.MAC, Address: system.Address})
	}
	return result
}

type MediaConfig struct {
	Enabled           bool         `yaml:"enabled" json:"enabled"`
	MediaGiB          int          `yaml:"media_gib,omitempty" json:"media_gib,omitempty"`
	ApplicationDomain string       `yaml:"application_domain,omitempty" json:"application_domain,omitempty"`
	Aliases           MediaAliases `yaml:"aliases,omitempty" json:"aliases,omitempty"`
}

// ArrstackConfig is retained as an internal source compatibility alias.
type ArrstackConfig = MediaConfig

type ObservabilityConfig struct {
	Enabled      *bool                           `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	PublicDomain string                          `yaml:"public_domain,omitempty" json:"public_domain,omitempty"`
	Collection   ObservabilityCollectionBindings `yaml:"collection,omitempty" json:"collection,omitempty"`
	Logging      LoggingConfig                   `yaml:"logging,omitempty" json:"logging,omitempty"`
	Monitoring   MonitoringConfig                `yaml:"monitoring,omitempty" json:"monitoring,omitempty"`
	StatusPage   StatusPageConfig                `yaml:"statuspage,omitempty" json:"statuspage,omitempty"`
	Alerts       AlertsConfig                    `yaml:"alerts,omitempty" json:"alerts,omitempty"`
}

// ObservabilityCollectionBindings is the persisted, fixed-role allowlist for
// the shared observability runtime. Empty bindings are allowed before the
// first approved apply; once populated all three canonical IPv4 addresses are
// required and must be distinct.
type ObservabilityCollectionBindings struct {
	Controller  string `yaml:"controller,omitempty" json:"controller,omitempty"`
	ProxmoxHost string `yaml:"proxmox_host,omitempty" json:"proxmox_host,omitempty"`
	Runtime     string `yaml:"runtime,omitempty" json:"runtime,omitempty"`
}
type AlertsConfig struct {
	Pushover *PushoverConfig `yaml:"pushover,omitempty" json:"pushover,omitempty"`
}
type PushoverConfig struct {
	Enabled  *bool  `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Title    string `yaml:"title,omitempty" json:"title,omitempty"`
	Priority int    `yaml:"priority,omitempty" json:"priority,omitempty"`
}
type LoggingConfig struct {
	RetentionDays int `yaml:"retention_days,omitempty" json:"retention_days,omitempty"`
}
type MonitoringConfig struct {
	RetentionDays int           `yaml:"retention_days,omitempty" json:"retention_days,omitempty"`
	Holmes        *HolmesConfig `yaml:"holmes,omitempty" json:"holmes,omitempty"`
}
type HolmesConfig struct {
	Enabled    *bool         `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	ModelAlias string        `yaml:"model_alias,omitempty" json:"model_alias,omitempty"`
	Bifrost    BifrostConfig `yaml:"bifrost,omitempty" json:"bifrost,omitempty"`
}
type BifrostConfig struct {
	ClientCredential string            `yaml:"client_credential,omitempty" json:"client_credential,omitempty"`
	Upstreams        []BifrostUpstream `yaml:"upstreams,omitempty" json:"upstreams,omitempty"`
	Models           []BifrostModel    `yaml:"models,omitempty" json:"models,omitempty"`
}
type BifrostUpstream struct {
	Name      string `yaml:"name" json:"name"`
	BaseURL   string `yaml:"base_url" json:"base_url"`
	SecretRef string `yaml:"secret_ref" json:"secret_ref"`
}
type BifrostModel struct {
	Alias    string `yaml:"alias" json:"alias"`
	Upstream string `yaml:"upstream" json:"upstream"`
	Model    string `yaml:"model" json:"model"`
}
type StatusPageConfig struct{}

// VPNConfig is provider-neutral inbound VPN intent. Clients are references
// to DHCP reservations; this block never creates or copies client identity.
type VPNConfig struct {
	Enabled  *bool        `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Location string       `yaml:"location,omitempty" json:"location,omitempty"`
	Clients  []string     `yaml:"clients,omitempty" json:"clients,omitempty"`
	Forwards []VPNForward `yaml:"forwards,omitempty" json:"forwards,omitempty"`
}

type VPNForward struct {
	Name        string   `yaml:"name" json:"name"`
	Reservation string   `yaml:"reservation" json:"reservation"`
	Protocols   []string `yaml:"protocols" json:"protocols"`
	Port        int      `yaml:"port" json:"port"`
}

// TailnetConfig contains only desired capability state, never credentials.
type TailnetConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}

type DNSConfig struct {
	Enabled        *bool         `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Upstreams      []DNSUpstream `yaml:"upstreams,omitempty" json:"upstreams,omitempty"`
	Records        []DNSRecord   `yaml:"records,omitempty" json:"records,omitempty"`
	Infrastructure []DNSRecord   `yaml:"infrastructure,omitempty" json:"infrastructure,omitempty"`
}

type DNSUpstream struct {
	Address string `yaml:"address" json:"address"`
	Port    int    `yaml:"port" json:"port"`
	TLSName string `yaml:"tls_name" json:"tls_name"`
	ECS     bool   `yaml:"ecs,omitempty" json:"ecs,omitempty"`
}

type DHCPConfig struct {
	Enabled       *bool         `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	LeaseDuration string        `yaml:"lease_duration,omitempty" json:"lease_duration,omitempty"`
	Scopes        []DHCPScope   `yaml:"scopes,omitempty" json:"scopes,omitempty"`
	Reservations  []Reservation `yaml:"reservations,omitempty" json:"reservations,omitempty"`
	Time          TimeConfig    `yaml:"time,omitempty" json:"time,omitempty"`
}

type DHCPScope struct {
	Zone         string `yaml:"zone" json:"zone"`
	Mode         string `yaml:"mode" json:"mode"`
	PoolStart    string `yaml:"pool_start,omitempty" json:"pool_start,omitempty"`
	PoolEnd      string `yaml:"pool_end,omitempty" json:"pool_end,omitempty"`
	PublishNames *bool  `yaml:"publish_names,omitempty" json:"publish_names,omitempty"`
}

type Reservation struct {
	Name    string `yaml:"name" json:"name"`
	Zone    string `yaml:"zone" json:"zone"`
	MAC     string `yaml:"mac" json:"mac"`
	Address string `yaml:"address" json:"address"`
}

type DNSRecord struct {
	Name  string `yaml:"name" json:"name"`
	Type  string `yaml:"type" json:"type"`
	Value string `yaml:"value" json:"value"`
}

type TimeConfig struct {
	Upstreams []string `yaml:"upstreams,omitempty" json:"upstreams,omitempty"`
	Serve     *bool    `yaml:"serve,omitempty" json:"serve,omitempty"`
}

func DefaultDNSUpstreams() []DNSUpstream {
	return []DNSUpstream{
		{Address: "9.9.9.9", Port: DNSResolverPort, TLSName: "dns.quad9.net"},
		{Address: "149.112.112.112", Port: DNSResolverPort, TLSName: "dns.quad9.net"},
	}
}

func DefaultTimeUpstreams() []string {
	// The first endpoint is a provider-published IPv4 bootstrap address. The
	// remaining entries provide independent IPv4 operators without requiring
	// DNS before the appliance can acquire time.
	return []string{"162.159.200.1", "17.253.34.125", "129.6.15.28"}
}

func DefaultScopes() []DHCPScope {
	return []DHCPScope{
		{Zone: "TRANSIT", Mode: ScopeReservationsOnly},
		{Zone: "INFRA", Mode: ScopeReservationsOnly},
		{Zone: "SERVERS", Mode: ScopePool, PoolStart: "10.10.20.100", PoolEnd: "10.10.20.199"},
		{Zone: "TRUSTED", Mode: ScopePool, PoolStart: "10.10.30.100", PoolEnd: "10.10.30.199"},
		{Zone: "SANDBOX", Mode: ScopePool, PoolStart: "10.10.40.100", PoolEnd: "10.10.40.199", PublishNames: boolPtr(false)},
		{Zone: "MGMT", Mode: ScopeReservationsOnly},
	}
}

func boolPtr(value bool) *bool { return &value }

func Enabled(pointer *bool) bool { return pointer != nil && *pointer }

// ResolveReservation returns a canonical DHCP reservation without creating a copy.
func ResolveReservation(modules Modules, name string) (Reservation, bool) {
	if modules.DHCP == nil {
		return Reservation{}, false
	}
	want := strings.ToLower(strings.TrimSpace(name))
	for _, reservation := range modules.DHCP.Reservations {
		if strings.ToLower(strings.TrimSpace(reservation.Name)) == want {
			return reservation, true
		}
	}
	return Reservation{}, false
}

func (m Modules) Normalize() Modules {
	result := m
	if result.Media == nil && result.Arrstack != nil {
		result.Media = result.Arrstack
	}
	if result.Media != nil {
		copyArr := *result.Media
		if copyArr.MediaGiB == 0 {
			copyArr.MediaGiB = 256
		}
		result.Media = &copyArr
		result.Arrstack = result.Media
	}
	if result.DNS != nil {
		copyDNS := *result.DNS
		if result.DNS.Enabled != nil {
			v := *result.DNS.Enabled
			copyDNS.Enabled = &v
		}
		copyDNS.Upstreams = append([]DNSUpstream(nil), result.DNS.Upstreams...)
		copyDNS.Records = append([]DNSRecord(nil), result.DNS.Records...)
		copyDNS.Infrastructure = append([]DNSRecord(nil), result.DNS.Infrastructure...)
		if Enabled(copyDNS.Enabled) && len(copyDNS.Upstreams) == 0 {
			copyDNS.Upstreams = DefaultDNSUpstreams()
		}
		result.DNS = &copyDNS
	}
	if result.DHCP != nil {
		copyDHCP := *result.DHCP
		if result.DHCP.Enabled != nil {
			v := *result.DHCP.Enabled
			copyDHCP.Enabled = &v
		}
		copyDHCP.Scopes = append([]DHCPScope(nil), result.DHCP.Scopes...)
		copyDHCP.Reservations = append([]Reservation(nil), result.DHCP.Reservations...)
		copyDHCP.Time.Upstreams = append([]string(nil), result.DHCP.Time.Upstreams...)
		if Enabled(copyDHCP.Enabled) {
			if copyDHCP.LeaseDuration == "" {
				copyDHCP.LeaseDuration = LeaseDuration12Hours
			}
			if len(copyDHCP.Scopes) == 0 {
				copyDHCP.Scopes = DefaultScopes()
			}
			if len(copyDHCP.Time.Upstreams) == 0 {
				copyDHCP.Time.Upstreams = DefaultTimeUpstreams()
			}
			if copyDHCP.Time.Serve == nil {
				copyDHCP.Time.Serve = boolPtr(true)
			}
		}
		result.DHCP = &copyDHCP
	}
	if result.VPN != nil {
		copyVPN := *result.VPN
		if result.VPN.Enabled != nil {
			v := *result.VPN.Enabled
			copyVPN.Enabled = &v
		}
		copyVPN.Clients = append([]string(nil), result.VPN.Clients...)
		copyVPN.Forwards = append([]VPNForward(nil), result.VPN.Forwards...)
		for i := range copyVPN.Forwards {
			copyVPN.Forwards[i].Protocols = append([]string(nil), result.VPN.Forwards[i].Protocols...)
		}
		result.VPN = &copyVPN
	}
	return result
}

func (m Modules) Clone() Modules {
	result := Modules{}
	result.Systems = append([]System(nil), m.Systems...)
	if m.Media != nil {
		copyMedia := *m.Media
		result.Media = &copyMedia
	}
	if m.Tailnet != nil {
		copyTailnet := *m.Tailnet
		result.Tailnet = &copyTailnet
	}
	if m.DNS != nil {
		copyDNS := *m.DNS
		if m.DNS.Enabled != nil {
			v := *m.DNS.Enabled
			copyDNS.Enabled = &v
		}
		copyDNS.Upstreams = append([]DNSUpstream(nil), m.DNS.Upstreams...)
		copyDNS.Records = append([]DNSRecord(nil), m.DNS.Records...)
		copyDNS.Infrastructure = append([]DNSRecord(nil), m.DNS.Infrastructure...)
		result.DNS = &copyDNS
	}
	if m.DHCP != nil {
		copyDHCP := *m.DHCP
		if m.DHCP.Enabled != nil {
			v := *m.DHCP.Enabled
			copyDHCP.Enabled = &v
		}
		copyDHCP.Scopes = append([]DHCPScope(nil), m.DHCP.Scopes...)
		copyDHCP.Reservations = append([]Reservation(nil), m.DHCP.Reservations...)
		copyDHCP.Time.Upstreams = append([]string(nil), m.DHCP.Time.Upstreams...)
		result.DHCP = &copyDHCP
	}
	if m.VPN != nil {
		copyVPN := *m.VPN
		if m.VPN.Enabled != nil {
			v := *m.VPN.Enabled
			copyVPN.Enabled = &v
		}
		copyVPN.Clients = append([]string(nil), m.VPN.Clients...)
		copyVPN.Forwards = append([]VPNForward(nil), m.VPN.Forwards...)
		for i := range copyVPN.Forwards {
			copyVPN.Forwards[i].Protocols = append([]string(nil), m.VPN.Forwards[i].Protocols...)
		}
		result.VPN = &copyVPN
	}
	if m.Observability != nil {
		v := *m.Observability
		if v.Enabled != nil {
			b := *v.Enabled
			v.Enabled = &b
		}
		if v.Alerts.Pushover != nil {
			p := *v.Alerts.Pushover
			if p.Enabled != nil {
				b := *p.Enabled
				p.Enabled = &b
			}
			v.Alerts.Pushover = &p
		}
		result.Observability = &v
	}
	if m.Observability != nil && m.Observability.Monitoring.Holmes != nil {
		v := *m.Observability.Monitoring.Holmes
		if v.Enabled != nil {
			b := *v.Enabled
			v.Enabled = &b
		}
		v.Bifrost.Upstreams = append([]BifrostUpstream(nil), v.Bifrost.Upstreams...)
		v.Bifrost.Models = append([]BifrostModel(nil), v.Bifrost.Models...)
		result.Observability.Monitoring.Holmes = &v
	}
	return result
}

func Validate(modules Modules, site model.Site) error {
	normalized := modules.Normalize()
	if err := validateSystems(normalized.Systems, site); err != nil {
		return err
	}
	normalized = SystemsExpanded(normalized)
	if len(normalized.Systems) > 0 && (normalized.DHCP == nil || !Enabled(normalized.DHCP.Enabled)) {
		return errors.New("registered systems require enabled DHCP")
	}
	for _, system := range normalized.Systems {
		if system.Monitoring && (normalized.Observability == nil || !Enabled(normalized.Observability.Enabled)) {
			return errors.New("monitored systems require enabled observability")
		}
	}
	if err := validateObservability(normalized); err != nil {
		return err
	}
	if normalized.Media != nil && normalized.Media.Enabled {
		if normalized.DNS == nil || !Enabled(normalized.DNS.Enabled) || normalized.DHCP == nil || !Enabled(normalized.DHCP.Enabled) || normalized.VPN == nil {
			return errors.New("enabled arrstack requires enabled DNS, DHCP, and configured VPN client intent")
		}
		if normalized.Media.MediaGiB < 1 {
			return errors.New("modules.media.media_gib must be positive")
		}
		if !ValidPublicDomain(normalized.Media.ApplicationDomain) {
			return errors.New("modules.media.application_domain must be a valid DNS domain")
		}
		aliases := []string{normalized.Media.Aliases.Radarr, normalized.Media.Aliases.Sonarr, normalized.Media.Aliases.Bazarr, normalized.Media.Aliases.Prowlarr, normalized.Media.Aliases.Trailarr}
		seenAliases := map[string]bool{}
		for _, alias := range aliases {
			if !validLabel(alias) || seenAliases[alias] {
				return errors.New("modules.media.aliases must be unique valid labels")
			}
			seenAliases[alias] = true
		}
		reservationFound, vpnClient := false, false
		for _, r := range normalized.DHCP.Reservations {
			if r.Name == "lab-media-01" && r.Zone == "SERVERS" && r.Address == "10.10.20.230" && r.MAC == "02:00:00:00:20:e6" {
				reservationFound = true
			}
		}
		for _, c := range normalized.VPN.Clients {
			if c == "lab-media-01" {
				vpnClient = true
			}
		}
		if !reservationFound || !vpnClient {
			return errors.New("enabled arrstack requires its fixed DHCP reservation and VPN client intent")
		}
		foundForward := false
		for _, f := range normalized.VPN.Forwards {
			if f.Name == "media-qbittorrent" && f.Reservation == "lab-media-01" && f.Port >= 1 && len(f.Protocols) == 2 && f.Protocols[0] == "tcp" && f.Protocols[1] == "udp" {
				foundForward = true
			}
		}
		if !foundForward {
			return errors.New("enabled arrstack requires the media-qbittorrent TCP/UDP forward")
		}
	}
	if normalized.Tailnet != nil && normalized.Tailnet.Enabled && (normalized.DNS == nil || !Enabled(normalized.DNS.Enabled) || normalized.DHCP == nil || !Enabled(normalized.DHCP.Enabled)) {
		return errors.New("enabled Tailnet requires enabled DNS and DHCP; teardown Tailnet first")
	}
	if normalized.DNS != nil {
		if err := validateDNS(normalized.DNS, site); err != nil {
			return err
		}
	}
	if normalized.DHCP != nil {
		if Enabled(normalized.DHCP.Enabled) && (normalized.DNS == nil || !Enabled(normalized.DNS.Enabled)) {
			return errors.New("enabled DHCP requires an enabled local DNS capability")
		}
		if err := validateDHCP(normalized.DHCP, site); err != nil {
			return err
		}
	}
	if normalized.VPN != nil {
		if err := validateVPN(normalized.VPN, normalized.DHCP); err != nil {
			return err
		}
	}
	if normalized.DNS != nil && (normalized.DHCP == nil || !Enabled(normalized.DHCP.Enabled)) {
		if err := validateSharedNames(normalized.DNS, &DHCPConfig{}, site); err != nil {
			return err
		}
	}
	if normalized.DNS != nil && normalized.DHCP != nil && Enabled(normalized.DNS.Enabled) && Enabled(normalized.DHCP.Enabled) {
		if err := validateSharedNames(normalized.DNS, normalized.DHCP, site); err != nil {
			return err
		}
	}
	return nil
}

func validateSystems(systems []System, site model.Site) error {
	platformNames := make(map[string]struct{})
	for _, component := range site.PlatformComponents() {
		if name, err := canonicalName(component.Hostname, site.Network.Domain); err == nil {
			platformNames[name] = struct{}{}
		}
		for _, alias := range component.DNSAliases {
			if name, err := canonicalName(alias, site.Network.Domain); err == nil {
				platformNames[name] = struct{}{}
			}
		}
	}
	for _, system := range systems {
		name := strings.TrimSpace(system.Name)
		if !model.IsDNSLabel(name) || name != strings.ToLower(name) {
			return fmt.Errorf("system name %q is invalid or non-canonical", system.Name)
		}
		canonical, err := canonicalName(name, site.Network.Domain)
		if err != nil {
			return fmt.Errorf("system name %q is invalid: %w", system.Name, err)
		}
		if _, exists := platformNames[canonical]; exists {
			return fmt.Errorf("system name %q conflicts with a platform name", system.Name)
		}
	}
	return nil
}

func validateObservability(modules Modules) error {
	if modules.Observability != nil {
		bindings := modules.Observability.Collection
		if bindings.Controller != "" || bindings.ProxmoxHost != "" || bindings.Runtime != "" {
			addresses := []string{bindings.Controller, bindings.ProxmoxHost, bindings.Runtime}
			seen := make(map[string]struct{}, len(addresses))
			for _, address := range addresses {
				parsed, err := netip.ParseAddr(address)
				if err != nil || !parsed.Is4() || parsed.String() != address {
					return errors.New("modules.observability.collection bindings must be canonical IPv4 addresses")
				}
				if _, ok := seen[address]; ok {
					return errors.New("modules.observability.collection bindings must use unique IPv4 addresses")
				}
				seen[address] = struct{}{}
			}
		}
	}
	if modules.Observability != nil && modules.Observability.PublicDomain != "" && !ValidPublicDomain(modules.Observability.PublicDomain) {
		return errors.New("modules.observability.public_domain must be a valid public DNS domain")
	}
	if modules.Observability != nil && modules.Observability.Logging.RetentionDays != 0 && (modules.Observability.Logging.RetentionDays < 1 || modules.Observability.Logging.RetentionDays > 3650) {
		return errors.New("modules.logging.retention_days must be between 1 and 3650 days")
	}
	if modules.Observability != nil && modules.Observability.Monitoring.RetentionDays != 0 && (modules.Observability.Monitoring.RetentionDays < 1 || modules.Observability.Monitoring.RetentionDays > 3650) {
		return errors.New("modules.monitoring.retention_days must be between 1 and 3650 days")
	}
	if modules.Observability != nil && modules.Observability.Alerts.Pushover != nil {
		pushover := modules.Observability.Alerts.Pushover
		if pushover.Priority == 2 || pushover.Priority < -2 || pushover.Priority > 1 {
			return errors.New("modules.observability.alerts.pushover.priority must be between -2 and 1")
		}
		if !validPushoverTitle(pushover.Title) {
			return errors.New("modules.observability.alerts.pushover.title is invalid")
		}
	}
	if modules.Observability != nil && modules.Observability.Monitoring.Holmes != nil && Enabled(modules.Observability.Monitoring.Holmes.Enabled) && !model.IsDNSLabel(modules.Observability.Monitoring.Holmes.ModelAlias) {
		return errors.New("modules.monitoring.holmes.model_alias must be a valid model alias when Holmes is enabled")
	}
	if modules.Observability != nil && modules.Observability.Monitoring.Holmes != nil && Enabled(modules.Observability.Monitoring.Holmes.Enabled) {
		h := modules.Observability.Monitoring.Holmes
		if h.Bifrost.ClientCredential != "holmes-client-token" {
			return errors.New("modules.monitoring.holmes.bifrost.client_credential must be holmes-client-token")
		}
		c := bifrost.Config{Listen: bifrost.DefaultListen, ClientCredential: h.Bifrost.ClientCredential}
		for _, u := range h.Bifrost.Upstreams {
			if !model.IsDNSLabel(u.SecretRef) {
				return fmt.Errorf("modules.observability.monitoring.holmes.bifrost upstream %q has an invalid secret_ref", u.Name)
			}
			c.Upstreams = append(c.Upstreams, bifrost.Upstream{Name: u.Name, BaseURL: u.BaseURL, Credential: u.SecretRef})
		}
		for _, m := range h.Bifrost.Models {
			c.Models = append(c.Models, bifrost.Model{Alias: m.Alias, Upstream: m.Upstream, Model: m.Model})
		}
		if err := c.Validate(); err != nil {
			return fmt.Errorf("modules.monitoring.holmes.bifrost: %w", err)
		}
	}
	return nil
}

// ValidPublicDomain accepts the DNS name used by the public Caddy frontend.
// It deliberately requires at least one dot so the name cannot be mistaken
// for a local host label or private network domain.
func ValidPublicDomain(value string) bool {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if value == "" || !strings.Contains(value, ".") || len(value) > 253 || strings.Contains(value, "..") {
		return false
	}
	for _, part := range strings.Split(value, ".") {
		if part == "" || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, char := range part {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
				return false
			}
		}
	}
	return true
}

func validLabel(value string) bool {
	if value == "" || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, char := range strings.ToLower(value) {
		if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
			return false
		}
	}
	return true
}

func validPushoverTitle(value string) bool {
	if len([]byte(value)) > 250 || value == "" {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == ' ' || char == '.' || char == '_' || char == '-') {
			return false
		}
	}
	return true
}

func validateVPN(config *VPNConfig, dhcp *DHCPConfig) error {
	if Enabled(config.Enabled) && strings.TrimSpace(config.Location) == "" {
		return errors.New("modules.vpn.location is required when VPN is enabled")
	}
	if dhcp == nil && (len(config.Clients) > 0 || len(config.Forwards) > 0) {
		return errors.New("VPN references require DHCP reservations")
	}
	reservations := map[string]Reservation{}
	if dhcp != nil {
		for _, r := range dhcp.Reservations {
			reservations[strings.ToLower(strings.TrimSpace(r.Name))] = r
		}
	}
	clients := map[string]struct{}{}
	for _, ref := range config.Clients {
		name := strings.ToLower(strings.TrimSpace(ref))
		if name == "" {
			return fmt.Errorf("modules.vpn client reference %q is empty", ref)
		}
		if _, ok := clients[name]; ok {
			return fmt.Errorf("modules.vpn.clients contains duplicate reservation %q", ref)
		}
		if !model.IsDNSLabel(name) {
			return fmt.Errorf("modules.vpn client %q is not a valid reservation name", ref)
		}
		if ref != name {
			return fmt.Errorf("modules.vpn client %q is not canonical", ref)
		}
		r, ok := reservations[name]
		if !ok {
			return fmt.Errorf("modules.vpn client %q does not reference a DHCP reservation", ref)
		}
		zone := strings.ToUpper(r.Zone)
		if zone != "SERVERS" && zone != "TRUSTED" && zone != "SANDBOX" {
			return fmt.Errorf("modules.vpn client %q uses unsupported zone %q", ref, r.Zone)
		}
		address, err := netip.ParseAddr(r.Address)
		if err != nil || !address.Is4() || address.String() != r.Address {
			return fmt.Errorf("modules.vpn client %q uses a non-canonical IPv4 address", ref)
		}
		subnet := map[string]string{"SERVERS": "10.10.20.0/24", "TRUSTED": "10.10.30.0/24", "SANDBOX": "10.10.40.0/24"}[zone]
		prefix, _ := netip.ParsePrefix(subnet)
		if !prefix.Contains(address) || address.As4()[3] < 224 || address.As4()[3] > 239 {
			return fmt.Errorf("modules.vpn client %q must be inside the %s .224-.239 range", ref, zone)
		}
		clients[name] = struct{}{}
	}
	seen := map[string]struct{}{}
	seenNames := map[string]struct{}{}
	for _, f := range config.Forwards {
		name := strings.ToLower(strings.TrimSpace(f.Name))
		reservation := strings.ToLower(strings.TrimSpace(f.Reservation))
		if name == "" || reservation == "" {
			return errors.New("modules.vpn forwards require name and reservation")
		}
		if !model.IsDNSLabel(name) {
			return fmt.Errorf("modules.vpn forward %q has invalid name", f.Name)
		}
		if f.Name != name || f.Reservation != reservation {
			return fmt.Errorf("modules.vpn forward %q has non-canonical name or reservation", f.Name)
		}
		if _, ok := seenNames[name]; ok {
			return fmt.Errorf("modules.vpn contains duplicate forward name %q", f.Name)
		}
		seenNames[name] = struct{}{}
		if _, ok := clients[reservation]; !ok {
			return fmt.Errorf("modules.vpn forward %q references a non-VPN client %q", f.Name, f.Reservation)
		}
		if f.Port < 1 || f.Port > 65535 {
			return fmt.Errorf("modules.vpn forward %q has invalid port %d", f.Name, f.Port)
		}
		if len(f.Protocols) == 0 {
			return fmt.Errorf("modules.vpn forward %q requires at least one protocol", f.Name)
		}
		for _, protocol := range f.Protocols {
			if protocol != strings.ToLower(strings.TrimSpace(protocol)) {
				return fmt.Errorf("modules.vpn forward %q has non-canonical protocol %q", f.Name, protocol)
			}
			if protocol != "tcp" && protocol != "udp" {
				return fmt.Errorf("modules.vpn forward %q has unsupported protocol %q", f.Name, protocol)
			}
			key := fmt.Sprintf("%s/%d", protocol, f.Port)
			if _, ok := seen[key]; ok {
				return fmt.Errorf("modules.vpn contains duplicate %s forward", key)
			}
			seen[key] = struct{}{}
		}
	}
	return nil
}

func validateDNS(config *DNSConfig, site model.Site) error {
	if !Enabled(config.Enabled) {
		return nil
	}
	if len(config.Upstreams) == 0 {
		return errors.New("modules.dns.upstreams must contain at least one encrypted resolver")
	}
	for _, upstream := range config.Upstreams {
		address := net.ParseIP(upstream.Address)
		if address == nil || address.To4() == nil || address.To4().String() != upstream.Address {
			return fmt.Errorf("modules.dns upstream address %q must be canonical IPv4", upstream.Address)
		}
		if upstream.Port != DNSResolverPort {
			return fmt.Errorf("modules.dns upstream %s must use TCP %d", upstream.Address, DNSResolverPort)
		}
		if upstream.TLSName != "dns.quad9.net" {
			return fmt.Errorf("modules.dns upstream %s must verify dns.quad9.net", upstream.Address)
		}
		if upstream.ECS {
			return errors.New("modules.dns upstream ECS must remain disabled")
		}
	}
	seen := map[string]struct{}{}
	seenNames := map[string]string{}
	owned := map[string]struct{}{}
	for _, component := range site.PlatformComponents() {
		if canonical, err := canonicalName(component.Hostname, site.Network.Domain); err == nil {
			owned[canonical] = struct{}{}
		}
		for _, alias := range component.DNSAliases {
			if canonical, err := canonicalName(alias, site.Network.Domain); err == nil {
				owned[canonical] = struct{}{}
			}
		}
	}
	for _, record := range config.Records {
		name, err := canonicalName(record.Name, site.Network.Domain)
		if err != nil {
			return fmt.Errorf("modules.dns record %q: %w", record.Name, err)
		}
		if record.Type != "A" && record.Type != "CNAME" {
			return fmt.Errorf("modules.dns record %s has unsupported type %q", name, record.Type)
		}
		key := name + "\x00" + record.Type
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate DNS record %s %s", name, record.Type)
		}
		if previous, exists := seenNames[name]; exists {
			return fmt.Errorf("DNS name %s cannot contain both %s and %s records", name, previous, record.Type)
		}
		if _, exists := owned[name]; exists {
			return fmt.Errorf("DNS record %s collides with a platform name", name)
		}
		seen[key] = struct{}{}
		seenNames[name] = record.Type
		if record.Type == "A" {
			address := net.ParseIP(record.Value)
			if address == nil || address.To4() == nil || address.To4().String() != record.Value || !addressInZone(address.To4(), site) {
				return fmt.Errorf("A record %s must contain a canonical IPv4 address", name)
			}
		} else {
			target, targetErr := canonicalName(record.Value, site.Network.Domain)
			if targetErr != nil {
				return fmt.Errorf("CNAME record %s: %w", name, targetErr)
			}
			if target == name {
				return fmt.Errorf("CNAME record %s cannot target itself", name)
			}
		}
	}
	return nil
}

func addressInZone(address net.IP, site model.Site) bool {
	for _, zone := range site.Network.Zones {
		_, prefix, err := net.ParseCIDR(zone.Network)
		if err == nil && prefix.Contains(address) {
			return true
		}
	}
	return false
}

func validateDHCP(config *DHCPConfig, site model.Site) error {
	if !Enabled(config.Enabled) {
		return nil
	}
	if config.LeaseDuration == "" {
		return errors.New("modules.dhcp.lease_duration is required")
	}
	if len(config.Scopes) != 6 {
		return errors.New("modules.dhcp.scopes must contain the six reference zones")
	}
	zones := zoneMap(site)
	seenZones := map[string]struct{}{}
	for _, scope := range config.Scopes {
		zone, ok := zones[strings.ToUpper(scope.Zone)]
		if !ok {
			return fmt.Errorf("modules.dhcp scope %q is not a reference zone", scope.Zone)
		}
		if _, exists := seenZones[zone.Name]; exists {
			return fmt.Errorf("duplicate DHCP scope %s", zone.Name)
		}
		seenZones[zone.Name] = struct{}{}
		if scope.Mode != ScopeReservationsOnly && scope.Mode != ScopePool {
			return fmt.Errorf("modules.dhcp scope %s has unsupported mode %q", zone.Name, scope.Mode)
		}
		if scope.Mode == ScopeReservationsOnly && (scope.PoolStart != "" || scope.PoolEnd != "") {
			return fmt.Errorf("reservation-only scope %s must not define a pool", zone.Name)
		}
		if scope.Mode == ScopePool {
			start, end, err := usablePool(scope.PoolStart, scope.PoolEnd, zone)
			if err != nil {
				return fmt.Errorf("modules.dhcp scope %s: %w", zone.Name, err)
			}
			if start == end {
				return fmt.Errorf("modules.dhcp scope %s pool is empty", zone.Name)
			}
			if overlapsProbeRange(start, end) {
				return fmt.Errorf("modules.dhcp scope %s pool overlaps reserved probe addresses", zone.Name)
			}
		}
	}
	if len(seenZones) != len(zones) {
		return errors.New("modules.dhcp.scopes must cover TRANSIT, INFRA, SERVERS, TRUSTED, SANDBOX, and MGMT")
	}
	seenNames := map[string]struct{}{}
	seenMACs := map[string]struct{}{}
	seenAddresses := map[string]struct{}{}
	for _, reservation := range config.Reservations {
		name := strings.ToLower(strings.TrimSpace(reservation.Name))
		if !model.IsDNSLabel(name) {
			return fmt.Errorf("DHCP reservation name %q is not a valid DNS label", reservation.Name)
		}
		if _, ok := seenNames[name]; ok {
			return fmt.Errorf("duplicate DHCP reservation name %q", name)
		}
		seenNames[name] = struct{}{}
		zone, ok := zones[strings.ToUpper(reservation.Zone)]
		if !ok {
			return fmt.Errorf("DHCP reservation %s uses unknown zone %q", name, reservation.Zone)
		}
		address, err := netip.ParseAddr(reservation.Address)
		if err != nil || !address.Is4() || address.String() != reservation.Address || !usableAddress(address, zone) {
			return fmt.Errorf("DHCP reservation %s address %q is outside usable %s addresses", name, reservation.Address, zone.Name)
		}
		if address.As4()[3] >= ProbeAddressStart && address.As4()[3] <= ProbeAddressEnd {
			return fmt.Errorf("DHCP reservation %s uses a reserved probe address", name)
		}
		mac, err := canonicalMAC(reservation.MAC)
		if err != nil {
			return fmt.Errorf("DHCP reservation %s: %w", name, err)
		}
		if _, exists := seenMACs[mac]; exists {
			return fmt.Errorf("duplicate DHCP reservation MAC %s", mac)
		}
		if _, exists := seenAddresses[reservation.Address]; exists {
			return fmt.Errorf("duplicate DHCP reservation address %s", reservation.Address)
		}
		seenNames[name], seenMACs[mac], seenAddresses[reservation.Address] = struct{}{}, struct{}{}, struct{}{}
		for _, scope := range config.Scopes {
			if strings.EqualFold(scope.Zone, zone.Name) && scope.Mode == ScopePool {
				poolStart, poolEnd, poolErr := usablePool(scope.PoolStart, scope.PoolEnd, zone)
				if poolErr == nil && address.Compare(poolStart) >= 0 && address.Compare(poolEnd) <= 0 {
					return fmt.Errorf("DHCP reservation %s address %s collides with dynamic pool %s", name, reservation.Address, zone.Name)
				}
			}
		}
	}
	if len(config.Time.Upstreams) < 1 {
		return errors.New("modules.dhcp.time.upstreams must contain at least one IPv4 NTP endpoint")
	}
	for _, upstream := range config.Time.Upstreams {
		address := net.ParseIP(upstream)
		if address == nil || address.To4() == nil || address.To4().String() != upstream {
			return fmt.Errorf("modules.dhcp.time upstream %q must be canonical IPv4", upstream)
		}
	}
	return nil
}

func validateSharedNames(dns *DNSConfig, dhcp *DHCPConfig, site model.Site) error {
	seen := map[string]struct{}{}
	for _, reservation := range dhcp.Reservations {
		name := strings.ToLower(reservation.Name) + "." + strings.ToLower(strings.TrimSuffix(site.Network.Domain, "."))
		seen[name] = struct{}{}
	}
	for _, component := range site.PlatformComponents() {
		if name, err := canonicalName(component.Hostname, site.Network.Domain); err == nil {
			seen[name] = struct{}{}
		}
		for _, alias := range component.DNSAliases {
			if name, err := canonicalName(alias, site.Network.Domain); err == nil {
				seen[name] = struct{}{}
			}
		}
	}
	cnameTargets := map[string]string{}
	for _, record := range dns.Records {
		name, err := canonicalName(record.Name, site.Network.Domain)
		if err != nil {
			return err
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("DNS record %s conflicts with a reservation-derived name", name)
		}
		if record.Type == "A" {
			seen[name] = struct{}{}
			continue
		}
		target, err := canonicalName(record.Value, site.Network.Domain)
		if err != nil {
			return err
		}
		cnameTargets[name] = target
		seen[name] = struct{}{}
	}
	var walk func(string, map[string]bool) error
	walk = func(name string, path map[string]bool) error {
		if path[name] {
			return fmt.Errorf("CNAME alias cycle includes %s", name)
		}
		target, isAlias := cnameTargets[name]
		if !isAlias {
			if _, known := seen[name]; !known {
				return fmt.Errorf("CNAME target %s is not a local record, reservation, or platform name", name)
			}
			return nil
		}
		path[name] = true
		if err := walk(target, path); err != nil {
			return err
		}
		delete(path, name)
		return nil
	}
	for name := range cnameTargets {
		if err := walk(name, map[string]bool{}); err != nil {
			return err
		}
	}
	return nil
}

func zoneMap(site model.Site) map[string]model.Zone {
	result := make(map[string]model.Zone, len(site.Network.Zones))
	for _, zone := range site.Network.Zones {
		result[strings.ToUpper(zone.Name)] = zone
	}
	return result
}

func usablePool(startValue, endValue string, zone model.Zone) (netip.Addr, netip.Addr, error) {
	start, err := netip.ParseAddr(startValue)
	if err != nil || !start.Is4() {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("pool_start %q is not an IPv4 address", startValue)
	}
	end, err := netip.ParseAddr(endValue)
	if err != nil || !end.Is4() {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("pool_end %q is not an IPv4 address", endValue)
	}
	if start.String() != startValue || end.String() != endValue || !usableAddress(start, zone) || !usableAddress(end, zone) || start.Compare(end) > 0 {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("pool %s-%s is not an ordered usable range in %s", startValue, endValue, zone.Name)
	}
	return start, end, nil
}

func usableAddress(address netip.Addr, zone model.Zone) bool {
	prefix, err := netip.ParsePrefix(zone.Network)
	if err != nil || !prefix.Contains(address) || address.String() == zone.Gateway {
		return false
	}
	last := prefix.Masked().Addr().As4()
	last[3] = 255
	return address.As4() != last
}

func overlapsProbeRange(start, end netip.Addr) bool {
	startOctet, endOctet := start.As4()[3], end.As4()[3]
	return endOctet >= ProbeAddressStart && startOctet <= ProbeAddressEnd
}

func canonicalMAC(value string) (string, error) {
	parsed, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil || len(parsed) != 6 {
		return "", fmt.Errorf("%q is not an Ethernet MAC address", value)
	}
	return strings.ToLower(parsed.String()), nil
}

func canonicalName(value, domain string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if name == "" || domain == "" {
		return "", errors.New("name and local domain are required")
	}
	if !strings.Contains(name, ".") {
		name += "." + domain
	}
	if name == domain || !strings.HasSuffix(name, "."+domain) {
		return "", fmt.Errorf("name must be inside %s", domain)
	}
	for _, label := range strings.Split(name, ".") {
		if !model.IsDNSLabel(label) {
			return "", fmt.Errorf("name contains invalid label %q", label)
		}
	}
	return name, nil
}

func CanonicalName(value, domain string) (string, error) { return canonicalName(value, domain) }
func CanonicalMAC(value string) (string, error)          { return canonicalMAC(value) }

func (m Modules) SortedRecords() []DNSRecord {
	if m.DNS == nil {
		return nil
	}
	result := append([]DNSRecord(nil), m.DNS.Records...)
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}
