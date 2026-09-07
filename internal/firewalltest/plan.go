package firewalltest

import (
	"fmt"
	"net/netip"
	"strconv"
)

// Fixtures derives the preferred temporary address without probing or
// mutating anything. The Host helper performs the bounded conflict check and
// may advance within the reserved .250-.254 range before assigning it.
func Fixtures(zones []Zone) ([]Zone, error) {
	result := append([]Zone(nil), zones...)
	for index := range result {
		prefix, err := netip.ParsePrefix(result[index].Subnet)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 24 {
			return nil, fmt.Errorf("zone %s does not have an IPv4 /24 subnet", result[index].Name)
		}
		address := netip.AddrFrom4([4]byte{prefix.Addr().As4()[0], prefix.Addr().As4()[1], prefix.Addr().As4()[2], 250})
		if !prefix.Contains(address) || address == netip.MustParseAddr(result[index].Gateway) {
			return nil, fmt.Errorf("zone %s cannot derive a temporary .250 address", result[index].Name)
		}
		result[index].Address = address.String()
		_ = index
	}
	return result, nil
}

func FixtureName(zone string) string {
	short := map[string]string{"TRANSIT": "t", "INFRA": "i", "SERVERS": "s", "TRUSTED": "r", "SANDBOX": "b", "MGMT": "m"}[zone]
	return "bt4a-" + short
}

func NamespaceName(zone string) string {
	return "bt4a-" + map[string]string{"TRANSIT": "transit", "INFRA": "infra", "SERVERS": "servers", "TRUSTED": "trusted", "SANDBOX": "sandbox", "MGMT": "mgmt"}[zone]
}

func CandidateAddresses(subnet string) ([]string, error) {
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 24 {
		return nil, fmt.Errorf("subnet %q is not an IPv4 /24", subnet)
	}
	base := prefix.Addr().As4()
	addresses := make([]string, 0, 5)
	for host := byte(250); host <= 254; host++ {
		addresses = append(addresses, netip.AddrFrom4([4]byte{base[0], base[1], base[2], host}).String())
	}
	return addresses, nil
}

func PortName(port int) string { return strconv.Itoa(port) }
