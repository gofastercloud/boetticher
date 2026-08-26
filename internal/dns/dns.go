package dns

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
)

const (
	AuthoritativeImplementation = model.AuthoritativeDNS
	AuthoritativeVersion        = model.AuthoritativeDNSVersion
	ConflictPolicy              = "reject-new-active-lease"
	TSIGSecretReference         = "secrets/homelab.sops.yaml#ddns_tsig_secret"
)

var hostnameLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

type Plan struct {
	ModelRevision         string         `json:"model_revision"`
	Implementation        string         `json:"authoritative_implementation"`
	ImplementationVersion string         `json:"authoritative_version"`
	StaticZone            string         `json:"static_zone"`
	Nameservers           []string       `json:"nameservers"`
	DynamicZones          []DynamicZone  `json:"dynamic_zones"`
	ReverseZones          []ReverseZone  `json:"reverse_zones"`
	StaticRecords         []StaticRecord `json:"static_records"`
	DDNS                  DDNSPlan       `json:"ddns"`
	AdGuardForwardZones   []string       `json:"adguard_forward_zones"`
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
	Enabled             bool     `json:"enabled"`
	Source              string   `json:"source"`
	UpdateTarget        string   `json:"update_target"`
	UpdateSources       []string `json:"update_sources"`
	TSIGSecretReference string   `json:"tsig_secret_reference"`
	ConflictPolicy      string   `json:"conflict_policy"`
	LeaseFailurePolicy  string   `json:"lease_failure_policy"`
	Replication         string   `json:"replication"`
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
		dynamic = append(dynamic, DynamicZone{Name: strings.ToLower(zone.Name) + "." + s.Network.Domain, SourceZone: zone.Name, Network: zone.Network, Gateway: zone.Gateway})
		reverse = append(reverse, ReverseZone{Name: reverseZone(zone.Network), Network: zone.Network})
	}
	static, err := staticRecords(s)
	if err != nil {
		return Plan{}, err
	}
	return Plan{
		ModelRevision: revision, Implementation: AuthoritativeImplementation, ImplementationVersion: AuthoritativeVersion,
		StaticZone: s.Network.Domain, Nameservers: []string{"10.10.20.10", "10.10.20.11"},
		DynamicZones: dynamic, ReverseZones: reverse, StaticRecords: static,
		DDNS: DDNSPlan{
			Enabled: true, Source: "OPNsense Kea D2", UpdateTarget: "PowerDNS Authoritative on lab-dns-01",
			UpdateSources: []string{"10.10.99.1"}, TSIGSecretReference: TSIGSecretReference,
			ConflictPolicy: ConflictPolicy, LeaseFailurePolicy: "lease-continues-without-DNS-registration", Replication: "PowerDNS AXFR/IXFR lab-dns-01 primary to lab-dns-02 secondary",
		},
		AdGuardForwardZones: append([]string{s.Network.Domain}, dynamicZoneNames(dynamic)...),
	}, nil
}

func staticRecords(s model.Site) ([]StaticRecord, error) {
	seen := map[string]bool{}
	result := make([]StaticRecord, 0)
	for _, module := range s.PlatformModules() {
		name := strings.ToLower(module.Hostname + "." + s.Network.Domain)
		if seen[name] {
			return nil, fmt.Errorf("duplicate static DNS name %s", name)
		}
		seen[name] = true
		result = append(result, StaticRecord{Name: name, Type: "A", Address: module.Address})
		for _, alias := range module.DNSAliases {
			aliasName := strings.ToLower(alias + "." + s.Network.Domain)
			if seen[aliasName] {
				return nil, fmt.Errorf("duplicate static DNS alias %s", aliasName)
			}
			seen[aliasName] = true
			result = append(result, StaticRecord{Name: aliasName, Type: "A", Address: module.Address})
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
