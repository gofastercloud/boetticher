package model

// EffectiveResolvers is the appliance-specific projection of the fixed DNS
// policy. It does not change ordinary zone defaults or a guest's gateway.
func EffectiveResolvers(s Site, c Component) []string {
	if c.Module == "firewall" {
		return []string{"9.9.9.9", "1.1.1.1"}
	}
	if c.Module == "airvpn" {
		return []string{"127.0.0.1"}
	}
	if s.ModuleConfig[c.Module].Network == ModuleNetworkAirVPN {
		return []string{AirVPNGuestAddress}
	}
	for _, z := range s.Network.Zones {
		if z.Name == "INFRA" {
			return append([]string(nil), z.DNSAddresses...)
		}
	}
	return nil
}

func ApplianceResolverMap(s Site) map[string][]string {
	result := map[string][]string{}
	for _, c := range s.PlatformComponents() {
		if c.ProductOwned {
			result[c.Name] = EffectiveResolvers(s, c)
		}
	}
	return result
}

func AirVPNSelectedNames(s Site) []string {
	names := []string{}
	for _, c := range s.PlatformComponents() {
		if c.ProductOwned && s.ModuleConfig[c.Module].Network == ModuleNetworkAirVPN {
			names = append(names, c.Name)
		}
	}
	return names
}
