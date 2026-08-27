package dns

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
)

const (
	AuthoritativeImplementation = model.AuthoritativeDNS
	AuthoritativeVersion        = model.AuthoritativeDNSVersion
	AuthoritativePort           = "5353"
	ConflictPolicy              = "reject-new-active-lease"
	TSIGSecretReference         = "secrets/boetticher.sops.yaml#ddns_tsig_secret"
)

var PublicUpstreams = []string{"https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query"}

var hostnameLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

type Plan struct {
	ModelRevision                string         `json:"model_revision"`
	Implementation               string         `json:"authoritative_implementation"`
	ImplementationVersion        string         `json:"authoritative_version"`
	PackageVersion               string         `json:"authoritative_package_version"`
	AuthoritativePort            string         `json:"authoritative_port"`
	AuthoritativeListenAddresses []string       `json:"authoritative_listen_addresses"`
	AuthoritativeForwardTarget   string         `json:"authoritative_forward_target"`
	StaticZone                   string         `json:"static_zone"`
	Nameservers                  []string       `json:"nameservers"`
	DynamicZones                 []DynamicZone  `json:"dynamic_zones"`
	ReverseZones                 []ReverseZone  `json:"reverse_zones"`
	StaticRecords                []StaticRecord `json:"static_records"`
	DDNS                         DDNSPlan       `json:"ddns"`
	AdGuardForwardZones          []string       `json:"adguard_forward_zones"`
	AdGuardReverseZones          []string       `json:"adguard_reverse_zones"`
	RecursiveProvider            string         `json:"recursive_provider"`
	RecursiveUpstreams           []string       `json:"recursive_upstreams"`
	AuthoritativeForwardZones    []string       `json:"authoritative_forward_zones"`
	AuthoritativeReverseZones    []string       `json:"authoritative_reverse_zones"`
	AuthoritativeNXDOMAINNoLeak  bool           `json:"authoritative_nxdomain_no_public_leak"`
}

type DynamicZone struct {
	Name       string `json:"name"`
	SourceZone string `json:"source_zone"`
	Network    string `json:"network"`
	Gateway    string `json:"gateway"`
}

type ReverseZone struct {
	Name    string `json:"name"`
	Network string `json:"network"`
}

type StaticRecord struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Address string `json:"address"`
}

type DDNSPlan struct {
	Enabled             bool       `json:"enabled"`
	Source              string     `json:"source"`
	UpdateTarget        string     `json:"update_target"`
	UpdateSources       []string   `json:"update_sources"`
	TSIGSecretReference string     `json:"tsig_secret_reference"`
	ConflictPolicy      string     `json:"conflict_policy"`
	LeaseFailurePolicy  string     `json:"lease_failure_policy"`
	Replication         string     `json:"replication"`
	TSIGAlgorithm       string     `json:"tsig_algorithm"`
	Zones               []DDNSZone `json:"zones"`
}

type DDNSZone struct {
	SourceZone  string `json:"source_zone"`
	ForwardZone string `json:"forward_zone"`
	ReverseZone string `json:"reverse_zone"`
	TSIGKeyName string `json:"tsig_key_name"`
}

type Lease struct {
	LeaseID string
	Name    string
	Address string
	State   string
	Active  bool
}

type RecordUpdate struct {
	Action      string `json:"action"`
	ForwardName string `json:"forward_name"`
	ReverseName string `json:"reverse_name"`
	Address     string `json:"address"`
	Zone        string `json:"zone"`
	LeaseID     string `json:"lease_id"`
}

type Conflict struct {
	Existing Lease
	Incoming Lease
}

func (c Conflict) Error() string {
	return fmt.Sprintf("active DHCP name conflict: lease %s already owns %s", c.Existing.LeaseID, c.Existing.Name)
}

func PlanFromSite(s model.Site) (Plan, error) {
	if err := s.Validate(); err != nil {
		return Plan{}, err
	}
	revision, err := s.Revision()
	if err != nil {
		return Plan{}, err
	}
	zones := s.Normalize().Network.Zones
	dynamic := make([]DynamicZone, 0, len(zones))
	reverse := make([]ReverseZone, 0, len(zones))
	for _, zone := range zones {
		if zone.Type != model.ZoneTypeTrusted && zone.Type != model.ZoneTypeSandbox {
			continue
		}
		dynamic = append(dynamic, DynamicZone{Name: strings.ToLower(zone.Name) + "." + s.Network.Domain, SourceZone: zone.Name, Network: zone.Network, Gateway: zone.Gateway})
		reverse = append(reverse, ReverseZone{Name: reverseZone(zone.Network), Network: zone.Network})
	}
	static, err := staticRecords(s)
	if err != nil {
		return Plan{}, err
	}
	ddnsZones := make([]DDNSZone, 0, len(dynamic))
	for index, zone := range dynamic {
		ddnsZones = append(ddnsZones, DDNSZone{SourceZone: zone.SourceZone, ForwardZone: zone.Name, ReverseZone: reverse[index].Name, TSIGKeyName: TSIGKeyName(zone.SourceZone, s.Network.Domain)})
	}
	listenAddresses := []string{"127.0.0.1", "10.10.10.10"}
	ddns := DDNSPlan{
		Enabled: true, Source: "Kea D2 on lab-fw-01", UpdateTarget: "10.10.10.10:" + AuthoritativePort,
		UpdateSources: []string{"10.10.99.1"}, TSIGSecretReference: TSIGSecretReference,
		ConflictPolicy: ConflictPolicy, LeaseFailurePolicy: "lease-continues-without-DNS-registration", Replication: "PowerDNS AXFR/IXFR lab-dns-01 primary to lab-dns-02 secondary on port " + AuthoritativePort,
		TSIGAlgorithm: "hmac-sha256", Zones: ddnsZones,
	}
	if s.Gateway.Mode == model.GatewayModeExternal {
		ddns.Enabled = false
		ddns.Source = "External DHCP/DDNS contract"
		ddns.UpdateSources = nil
		ddns.LeaseFailurePolicy = "external DHCP may omit automatic workload registration"
	}
	provider := s.ModuleConfig["dns"].Provider
	if provider == "" {
		provider = string(model.DNSProviderBlocky)
	}
	authoritativeForwardZones := append([]string{s.Network.Domain}, dynamicZoneNames(dynamic)...)
	authoritativeReverseZones := reverseZoneNames(reverse)
	return Plan{
		ModelRevision: revision, Implementation: AuthoritativeImplementation, ImplementationVersion: AuthoritativeVersion, PackageVersion: model.AuthoritativePackageVersion, AuthoritativePort: AuthoritativePort,
		AuthoritativeListenAddresses: listenAddresses, AuthoritativeForwardTarget: listenAddresses[0] + ":" + AuthoritativePort,
		StaticZone: s.Network.Domain, Nameservers: []string{"10.10.10.10", "10.10.10.11"},
		DynamicZones: dynamic, ReverseZones: reverse, StaticRecords: static,
		DDNS:                ddns,
		AdGuardForwardZones: authoritativeForwardZones, AdGuardReverseZones: authoritativeReverseZones,
		RecursiveProvider: provider, RecursiveUpstreams: append([]string(nil), PublicUpstreams...),
		AuthoritativeForwardZones: authoritativeForwardZones, AuthoritativeReverseZones: authoritativeReverseZones,
		AuthoritativeNXDOMAINNoLeak: true,
	}, nil
}

// TSIGKeyName is the single naming contract shared by Kea and PowerDNS.
func TSIGKeyName(sourceZone, domain string) string {
	return strings.ToLower(strings.TrimSuffix(sourceZone, ".")) + ".ddns." + strings.ToLower(strings.TrimSuffix(domain, ".")) + "."
}

func staticRecords(s model.Site) ([]StaticRecord, error) {
	seen := map[string]string{}
	result := make([]StaticRecord, 0)
	add := func(name, address string) error {
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		if existing, ok := seen[name]; ok {
			if existing != address {
				return fmt.Errorf("duplicate static DNS name %s", name)
			}
			return nil
		}
		seen[name] = address
		result = append(result, StaticRecord{Name: name, Type: "A", Address: address})
		return nil
	}
	for _, module := range s.PlatformComponents() {
		name := strings.ToLower(module.Hostname + "." + s.Network.Domain)
		if err := add(name, module.Address); err != nil {
			return nil, err
		}
		for _, alias := range module.DNSAliases {
			aliasName := strings.ToLower(alias + "." + s.Network.Domain)
			if err := add(aliasName, module.Address); err != nil {
				return nil, fmt.Errorf("duplicate static DNS alias %s: %w", aliasName, err)
			}
		}
		if module.URL != "" {
			parsed, err := url.Parse(module.URL)
			if err != nil {
				return nil, fmt.Errorf("component %s has invalid URL: %w", module.Name, err)
			}
			host := strings.ToLower(parsed.Hostname())
			if strings.HasSuffix(host, "."+strings.ToLower(s.Network.Domain)) {
				if err := add(host, module.Address); err != nil {
					return nil, fmt.Errorf("component %s URL: %w", module.Name, err)
				}
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func dynamicZoneNames(zones []DynamicZone) []string {
	result := make([]string, 0, len(zones))
	for _, zone := range zones {
		result = append(result, zone.Name)
	}
	sort.Strings(result)
	return result
}

func reverseZoneNames(zones []ReverseZone) []string {
	result := make([]string, 0, len(zones))
	for _, zone := range zones {
		result = append(result, zone.Name)
	}
	sort.Strings(result)
	return result
}

func QualifiedName(s model.Site, zoneName, raw string) (string, error) {
	var zone DynamicZone
	plan, err := PlanFromSite(s)
	if err != nil {
		return "", err
	}
	for _, candidate := range plan.DynamicZones {
		if candidate.SourceZone == zoneName {
			zone = candidate
			break
		}
	}
	if zone.Name == "" {
		return "", fmt.Errorf("unknown dynamic DNS zone %q", zoneName)
	}
	label, err := clientLabel(raw)
	if err != nil {
		return "", err
	}
	name := label + "." + zone.Name
	for _, record := range plan.StaticRecords {
		if record.Name == name || strings.SplitN(record.Name, ".", 2)[0] == label {
			return "", fmt.Errorf("dynamic name label %s is platform-owned", label)
		}
	}
	return name, nil
}

func clientLabel(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if value == "" {
		return "", fmt.Errorf("DHCP hostname is empty or invalid")
	}
	parts := strings.Split(value, ".")
	for _, part := range parts {
		if !hostnameLabel.MatchString(part) {
			return "", fmt.Errorf("DHCP hostname %q contains an unsafe label", raw)
		}
	}
	return parts[0], nil
}

func BuildLeaseUpdate(s model.Site, zoneName string, lease Lease) (RecordUpdate, error) {
	if lease.LeaseID == "" {
		return RecordUpdate{}, fmt.Errorf("lease ID is required")
	}
	zone, err := zoneFor(s, zoneName)
	if err != nil {
		return RecordUpdate{}, err
	}
	if lease.State == "released" || lease.State == "expired" || !lease.Active {
		name, err := QualifiedName(s, zoneName, lease.Name)
		if err != nil {
			return RecordUpdate{}, err
		}
		return RecordUpdate{Action: "delete", ForwardName: name, ReverseName: reverseName(lease.Address), Address: lease.Address, Zone: zone.Name, LeaseID: lease.LeaseID}, nil
	}
	name, err := QualifiedName(s, zoneName, lease.Name)
	if err != nil {
		return RecordUpdate{}, err
	}
	ip := net.ParseIP(lease.Address)
	if ip == nil || ip.To4() == nil || !ipInNetwork(ip, zone.Network) {
		return RecordUpdate{}, fmt.Errorf("lease address %q is outside %s", lease.Address, zone.Network)
	}
	return RecordUpdate{Action: "upsert", ForwardName: name, ReverseName: reverseName(lease.Address), Address: ip.To4().String(), Zone: zone.Name, LeaseID: lease.LeaseID}, nil
}

// BuildLeaseReplacement emits the lifecycle changes needed when a DHCP
// identity moves or a new lease replaces an old active lease. Keeping the old
// delete explicit prevents stale A/PTR records from surviving a replacement.
func BuildLeaseReplacement(s model.Site, zoneName string, previous, current Lease) ([]RecordUpdate, error) {
	if previous.LeaseID != "" && (previous.LeaseID != current.LeaseID || previous.Address != current.Address || previous.Name != current.Name) {
		old, err := BuildLeaseUpdate(s, zoneName, Lease{
			LeaseID: previous.LeaseID, Name: previous.Name, Address: previous.Address,
			State: "released", Active: false,
		})
		if err != nil {
			return nil, err
		}
		newUpdate, err := BuildLeaseUpdate(s, zoneName, current)
		if err != nil {
			return nil, err
		}
		return []RecordUpdate{old, newUpdate}, nil
	}
	update, err := BuildLeaseUpdate(s, zoneName, current)
	if err != nil {
		return nil, err
	}
	return []RecordUpdate{update}, nil
}

func ResolveConflict(existing, incoming Lease) (string, error) {
	if existing.LeaseID == "" {
		return "accept", nil
	}
	if existing.LeaseID == incoming.LeaseID {
		return "update", nil
	}
	if existing.Active && incoming.Active {
		return "reject", Conflict{Existing: existing, Incoming: incoming}
	}
	return "replace", nil
}

func zoneFor(s model.Site, name string) (DynamicZone, error) {
	plan, err := PlanFromSite(s)
	if err != nil {
		return DynamicZone{}, err
	}
	for _, zone := range plan.DynamicZones {
		if zone.SourceZone == name {
			return zone, nil
		}
	}
	return DynamicZone{}, fmt.Errorf("unknown dynamic DNS zone %q", name)
}

func ipInNetwork(ip net.IP, network string) bool {
	_, subnet, err := net.ParseCIDR(network)
	return err == nil && subnet.Contains(ip)
}

func reverseZone(network string) string {
	base, parsed, err := net.ParseCIDR(network)
	if err != nil {
		return ""
	}
	ones, bits := parsed.Mask.Size()
	if bits != 32 || ones != 24 {
		return ""
	}
	octets := strings.Split(base.To4().String(), ".")
	return strings.Join([]string{octets[2], octets[1], octets[0], "in-addr.arpa"}, ".")
}

func reverseName(address string) string {
	ip := net.ParseIP(address).To4()
	if ip == nil {
		return ""
	}
	octets := strings.Split(ip.String(), ".")
	return strings.Join([]string{octets[3], octets[2], octets[1], octets[0], "in-addr.arpa"}, ".")
}
