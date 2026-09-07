package firewallmodule

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	"github.com/gofastercloud/boetticher/internal/model"
)

const (
	serviceDNSMasqSection = "boetticher_dnsmasq"
	serviceStubbyGlobal   = "boetticher_global"
	serviceNTPSection     = "ntp"
)

// ServiceState is the composed native configuration owned by the DHCP/DNS
// peers. Both handlers reconcile this complete scope so one cannot delete the
// other's dnsmasq or time settings.
type ServiceState struct {
	DHCP     []Section
	Stubby   []Section
	System   []Section
	Firewall []Section
}

func ServiceStateFromModules(site model.Site, modules clientservices.Modules) (ServiceState, error) {
	normalized := modules.Normalize()
	if err := clientservices.Validate(normalized, site); err != nil {
		return ServiceState{}, err
	}
	dnsEnabled := normalized.DNS != nil && clientservices.Enabled(normalized.DNS.Enabled)
	dhcpEnabled := normalized.DHCP != nil && clientservices.Enabled(normalized.DHCP.Enabled)
	state := ServiceState{}
	state.DHCP = append(state.DHCP, dnsmasqSections(site, normalized)...)
	if dnsEnabled {
		state.DHCP = append(state.DHCP, dnsRecordSections(site, normalized.DNS.Records)...)
		state.Stubby = stubbySections(normalized.DNS.Upstreams)
	}
	// Appliance upstream time is independent of client-facing DHCP/NTP. Once
	// the service contract is applied, retain the exact native time settings.
	ntpUpstreams := clientservices.DefaultTimeUpstreams()
	var ntpServe *bool
	if normalized.DHCP != nil && len(normalized.DHCP.Time.Upstreams) > 0 {
		ntpUpstreams = normalized.DHCP.Time.Upstreams
		ntpServe = normalized.DHCP.Time.Serve
		if !clientservices.Enabled(normalized.DHCP.Enabled) {
			falseValue := false
			ntpServe = &falseValue
		}
	}
	state.System = append(state.System, ntpSections(ntpUpstreams, ntpServe)...)
	state.Firewall = serviceFirewallSections(site, dnsEnabled, dhcpEnabled)
	return state, nil
}

func dnsmasqSections(site model.Site, modules clientservices.Modules) []Section {
	dnsEnabled := modules.DNS != nil && clientservices.Enabled(modules.DNS.Enabled)
	dhcpEnabled := modules.DHCP != nil && clientservices.Enabled(modules.DHCP.Enabled)
	options := map[string]string{
		"domainneeded":      "1",
		"boguspriv":         "1",
		"noresolv":          "1",
		"localservice":      "1",
		"rebind_protection": "1",
		"leasefile":         clientservices.LeaseFilePath,
		"domain":            site.Network.Domain,
	}
	lists := map[string][]string{}
	if dnsEnabled {
		options["local"] = "/" + site.Network.Domain + "/"
		lists["server"] = []string{clientservices.StubbyListenAddress}
	}
	sections := []Section{
		{Name: serviceDNSMasqSection, Type: "dnsmasq", Options: options, Lists: lists},
		{Name: "boetticher_home", Type: "dhcp", Options: map[string]string{
			"interface": "boetticher_home",
			"ignore":    "1",
			"ra":        "disabled",
			"dhcpv6":    "disabled",
			"ndp":       "disabled",
		}, Lists: map[string][]string{}},
	}
	if !dhcpEnabled {
		return sections
	}
	for _, scope := range modules.DHCP.Scopes {
		zone, ok := zoneByName(site, scope.Zone)
		if !ok {
			continue
		}
		name := strings.ToLower(zone.Name)
		options := map[string]string{
			"interface":   "boetticher_iface_" + name,
			"leasetime":   modules.DHCP.LeaseDuration,
			"start":       "0",
			"limit":       "0",
			"dynamicdhcp": "0",
			"force":       "1",
		}
		lists := map[string][]string{
			"dhcp_option": {
				"3," + zone.Gateway,
				"6," + zone.Gateway,
				"15," + site.Network.Domain,
				"42," + zone.Gateway,
			},
		}
		if scope.Mode == clientservices.ScopePool {
			start := net.ParseIP(scope.PoolStart).To4()
			end := net.ParseIP(scope.PoolEnd).To4()
			if start != nil && end != nil {
				options["start"] = strconv.Itoa(int(start[3]))
				options["limit"] = strconv.Itoa(int(end[3] - start[3] + 1))
				options["dynamicdhcp"] = "1"
			}
		}
		if scope.PublishNames != nil && !*scope.PublishNames {
			options["dhcp_ignore_names"] = "1"
		}
		sections = append(sections, Section{Name: "boetticher_dhcp_" + name, Type: "dhcp", Options: options, Lists: lists})
	}
	for _, reservation := range modules.DHCP.Reservations {
		name := strings.ToLower(reservation.Name)
		sections = append(sections, Section{Name: "boetticher_host_" + name, Type: "host", Options: map[string]string{"name": name, "mac": reservation.MAC, "ip": reservation.Address}, Lists: map[string][]string{}})
	}
	return sections
}

func dnsRecordSections(site model.Site, records []clientservices.DNSRecord) []Section {
	sections := make([]Section, 0, len(records))
	for _, record := range records {
		name, err := clientservices.CanonicalName(record.Name, site.Network.Domain)
		if err != nil {
			continue
		}
		safe := strings.NewReplacer(".", "_", "-", "_").Replace(strings.TrimSuffix(name, "."))
		switch record.Type {
		case "A":
			sections = append(sections, Section{Name: "boetticher_record_" + safe, Type: "hostrecord", Options: map[string]string{"name": name, "ip": record.Value}, Lists: map[string][]string{}})
		case "CNAME":
			target, targetErr := clientservices.CanonicalName(record.Value, site.Network.Domain)
			if targetErr != nil {
				continue
			}
			sections = append(sections, Section{Name: "boetticher_cname_" + safe, Type: "cname", Options: map[string]string{"cname": name, "target": target}, Lists: map[string][]string{}})
		}
	}
	return sections
}

func stubbySections(upstreams []clientservices.DNSUpstream) []Section {
	sections := []Section{{Name: serviceStubbyGlobal, Type: "stubby", Options: map[string]string{
		"trigger":                    "none",
		"tls_min_version":            "1.2",
		"edns_client_subnet_private": "1",
		"round_robin_upstreams":      "1",
	}, Lists: map[string][]string{"listen_address": {"127.0.0.1@5453"}}}}
	for _, upstream := range upstreams {
		safe := strings.ReplaceAll(upstream.Address, ".", "_")
		sections = append(sections, Section{Name: "boetticher_resolver_" + safe, Type: "resolver", Options: map[string]string{
			"address":            upstream.Address,
			"tls_auth_name":      upstream.TLSName,
			"tls_port":           strconv.Itoa(upstream.Port),
			"tls_authentication": "1",
		}, Lists: map[string][]string{}})
	}
	return sections
}

func ntpSections(upstreams []string, serve *bool) []Section {
	enableServer := "0"
	if serve != nil && *serve {
		enableServer = "1"
	}
	return []Section{{Name: serviceNTPSection, Type: "timeserver", Options: map[string]string{"enable_server": enableServer}, Lists: map[string][]string{"server": append([]string(nil), upstreams...)}}}
}

func serviceFirewallSections(site model.Site, dnsEnabled, dhcpEnabled bool) []Section {
	if !dnsEnabled && !dhcpEnabled {
		return nil
	}
	sections := make([]Section, 0, len(site.Network.Zones)*5)
	for _, zone := range site.Network.Zones {
		name := strings.ToLower(zone.Name)
		if dhcpEnabled {
			sections = append(sections, Section{Name: "boetticher_allow_" + name + "_dhcp", Type: "rule", Options: map[string]string{"name": "Boetticher " + zone.Name + " DHCP", "src": name, "proto": "udp", "src_port": "68", "dest_port": "67", "family": "ipv4", "target": "ACCEPT"}, Lists: map[string][]string{}})
			sections = append(sections, Section{Name: "boetticher_deny_" + name + "_external_dhcp", Type: "rule", Options: map[string]string{"name": "Boetticher " + zone.Name + " deny external DHCP", "src": name, "dest": "home_wan", "proto": "udp", "dest_port": "67", "family": "ipv4", "target": "DROP"}, Lists: map[string][]string{}})
		}
		if dnsEnabled {
			for _, protocol := range []string{"tcp", "udp"} {
				sections = append(sections, Section{Name: "boetticher_allow_" + name + "_dns_" + protocol, Type: "rule", Options: map[string]string{"name": "Boetticher " + zone.Name + " DNS " + protocol, "src": name, "proto": protocol, "dest_port": "53", "family": "ipv4", "target": "ACCEPT"}, Lists: map[string][]string{}})
			}
			for _, item := range []struct{ suffix, protocol, port string }{{"dns_udp", "udp", "53"}, {"dns_tcp", "tcp", "53"}, {"dot_tcp", "tcp", "853"}} {
				sections = append(sections, Section{Name: "boetticher_deny_" + name + "_external_" + item.suffix, Type: "rule", Options: map[string]string{"name": "Boetticher " + zone.Name + " deny external " + item.suffix, "src": name, "dest": "home_wan", "proto": item.protocol, "dest_port": item.port, "family": "ipv4", "target": "DROP"}, Lists: map[string][]string{}})
			}
		}
		if dhcpEnabled {
			sections = append(sections, Section{Name: "boetticher_allow_" + name + "_ntp", Type: "rule", Options: map[string]string{"name": "Boetticher " + zone.Name + " NTP", "src": name, "proto": "udp", "dest_port": "123", "family": "ipv4", "target": "ACCEPT"}, Lists: map[string][]string{}})
			sections = append(sections, Section{Name: "boetticher_deny_" + name + "_external_ntp", Type: "rule", Options: map[string]string{"name": "Boetticher " + zone.Name + " deny external NTP", "src": name, "dest": "home_wan", "proto": "udp", "dest_port": "123", "family": "ipv4", "target": "DROP"}, Lists: map[string][]string{}})
		}
	}
	return sections
}

func zoneByName(site model.Site, name string) (model.Zone, bool) {
	for _, zone := range site.Network.Zones {
		if strings.EqualFold(zone.Name, name) {
			return zone, true
		}
	}
	return model.Zone{}, false
}

// ValidateServiceState is a small guard for provider-specific callers that
// need a useful error before attempting a native mutation.
func ValidateServiceState(state ServiceState) error {
	if len(state.Stubby) > 0 && len(state.DHCP) == 0 {
		return fmt.Errorf("stubby configuration requires the shared dnsmasq scope")
	}
	return nil
}
