package firewallmodule

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

const (
	SafetyProtectedSet  = "boetticher_vpn_protected4"
	SafetyClientSet     = "boetticher_vpn_clients4"
	SafetyForwardTCPSet = "boetticher_vpn_forwards_tcp4"
	SafetyForwardUDPSet = "boetticher_vpn_forwards_udp4"
	SafetyHomeSet       = "boetticher_home4"
	SafetyLabSet        = "boetticher_lab4"
	SafetyGuardVersion  = "v1"
)

var safetyAssetPaths = []string{
	"/usr/share/nftables.d/chain-pre/input/10-boetticher-safety.nft",
	"/usr/share/nftables.d/chain-pre/forward/10-boetticher-safety.nft",
	"/usr/share/nftables.d/chain-pre/output/10-boetticher-safety.nft",
}

// ForwardTuple is deliberately small. It is the native destination tuple
// used to revoke an inbound forwarding permission; it is not an operator
// authored nftables rule.
type ForwardTuple struct {
	Address  string
	Protocol string
	Port     uint16
}

// SafetyConfig contains only the data projected into native firewall sets.
// The guard itself is static and never carries reservation or client intent.
type SafetyConfig struct {
	ProtectedIPv4 []string
	ClientIPv4    []string
	HomeIPv4      []string
	LabIPv4       []string
	ForwardTuples []ForwardTuple
}

func DefaultSafetyConfig() SafetyConfig {
	return SafetyConfig{
		ProtectedIPv4: []string{"10.10.10.224/28", "10.10.20.224/28", "10.10.30.224/28", "10.10.40.224/28"},
		HomeIPv4:      []string{"192.168.4.0/22"},
		LabIPv4:       []string{"10.10.5.0/24", "10.10.10.0/24", "10.10.20.0/24", "10.10.30.0/24", "10.10.40.0/24", "10.10.99.0/24"},
	}
}

func (c SafetyConfig) Validate() error {
	if len(c.ProtectedIPv4) == 0 || len(c.HomeIPv4) == 0 || len(c.LabIPv4) == 0 {
		return fmt.Errorf("protected, HOME, and LAB IPv4 sets must not be empty")
	}
	protected := make([]netip.Prefix, 0, len(c.ProtectedIPv4))
	for _, raw := range c.ProtectedIPv4 {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 28 || prefix != prefix.Masked() || prefix.String() != raw {
			return fmt.Errorf("protected IPv4 range %q must be canonical /28", raw)
		}
		for _, existing := range protected {
			if existing.Overlaps(prefix) {
				return fmt.Errorf("protected IPv4 ranges %q and %q overlap", existing, raw)
			}
		}
		protected = append(protected, prefix)
	}
	for _, set := range [][]string{c.HomeIPv4, c.LabIPv4} {
		for _, raw := range set {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.String() != raw {
				return fmt.Errorf("IPv4 prefix %q must be canonical", raw)
			}
		}
	}
	for _, raw := range c.ClientIPv4 {
		address, err := netip.ParseAddr(raw)
		if err != nil || !address.Is4() || address.String() != raw {
			return fmt.Errorf("VPN client address %q must be canonical IPv4", raw)
		}
		if !containsAddress(protected, address) {
			return fmt.Errorf("VPN client address %q is outside a protected range", raw)
		}
	}
	for _, tuple := range c.ForwardTuples {
		address, err := netip.ParseAddr(tuple.Address)
		if err != nil || !address.Is4() || address.String() != tuple.Address {
			return fmt.Errorf("forward destination %q must be canonical IPv4", tuple.Address)
		}
		if !containsString(c.ClientIPv4, tuple.Address) {
			return fmt.Errorf("forward destination %q is not a declared VPN client", tuple.Address)
		}
		if tuple.Protocol != "tcp" && tuple.Protocol != "udp" {
			return fmt.Errorf("forward destination %s has unsupported protocol %q", tuple.Address, tuple.Protocol)
		}
		if tuple.Port == 0 {
			return fmt.Errorf("forward destination %s has an invalid port", tuple.Address)
		}
	}
	return nil
}

func containsString(values []string, value string) bool {
	for _, existing := range values {
		if existing == value {
			return true
		}
	}
	return false
}

func containsAddress(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

// RenderSafetyUCI returns the complete native ipset projection. Empty client
// and forwarding sets are intentional in the image baseline.
func RenderSafetyUCI(c SafetyConfig) (string, error) {
	sections, err := SafetySections(c)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, section := range sections {
		fmt.Fprintf(&b, "config ipset '%s'\n\toption name '%s'\n\toption family '%s'\n", section.Name, section.Options["name"], section.Options["family"])
		for _, match := range section.Lists["match"] {
			fmt.Fprintf(&b, "\tlist match '%s'\n", match)
		}
		for _, entry := range section.Lists["entry"] {
			fmt.Fprintf(&b, "\tlist entry '%s'\n", entry)
		}
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// SafetySections returns the complete native ipset projection used by the
// appliance composer and the packaged UCI renderer.
func SafetySections(c SafetyConfig) ([]Section, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	sections := []Section{}
	add := func(name string, matches, entries []string) {
		sections = append(sections, Section{Name: name, Type: "ipset", Options: map[string]string{"name": name, "family": "ipv4"}, Lists: map[string][]string{"match": matches, "entry": entries}})
	}
	add(SafetyProtectedSet, []string{"src_net"}, append([]string(nil), c.ProtectedIPv4...))
	add(SafetyClientSet, []string{"src_ip"}, append([]string(nil), c.ClientIPv4...))
	add(SafetyHomeSet, []string{"dest_net"}, append([]string(nil), c.HomeIPv4...))
	add(SafetyLabSet, []string{"dest_net"}, append([]string(nil), c.LabIPv4...))
	tcp, udp := []string{}, []string{}
	for _, tuple := range c.ForwardTuples {
		entry := tuple.Address + " " + strconv.Itoa(int(tuple.Port))
		if tuple.Protocol == "tcp" {
			tcp = append(tcp, entry)
		} else {
			udp = append(udp, entry)
		}
	}
	sort.Strings(tcp)
	sort.Strings(udp)
	add(SafetyForwardTCPSet, []string{"dest_ip", "dest_port"}, tcp)
	add(SafetyForwardUDPSet, []string{"dest_ip", "dest_port"}, udp)
	return sections, nil
}

// RenderSafetyAssetManifest is intentionally metadata only. `fw4 print` must
// identify source paths without copying expanded nftables body into the
// operator evidence; the gate separately verifies each packaged digest.
func RenderSafetyAssetManifest() string {
	return strings.Join(safetyAssetPaths, "\n") + "\n"
}
