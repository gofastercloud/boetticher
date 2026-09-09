package firewallmodule

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/openwrt"
	"github.com/gofastercloud/boetticher/internal/tailnet"
)

const (
	serviceDNSMasqSection               = "boetticher_dnsmasq"
	serviceStubbyGlobal                 = "global"
	serviceNTPSection                   = "ntp"
	observabilityControllerExporterRule = "boetticher_observability_controller_exporter"
	observabilityHostExporterRule       = "boetticher_observability_host_exporter"
	observabilityControllerIngressRule  = "boetticher_observability_controller_ingress"
	observabilityHostIngressRule        = "boetticher_observability_host_ingress"
	observabilityRuntimeIngressRule     = "boetticher_observability_runtime_ingress"
	observabilityTrustedIngressRule     = "boetticher_observability_trusted_ingress"
	observabilityTailnetIngressRule     = "boetticher_observability_tailnet_ingress"
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

// ValidateServicePackage rejects an active native instance outside the exact
// settings composed by this capability. UCI names alone are not ownership
// proof for global/factory sections, so conflicting instances are held for
// explicit operator resolution.
func ValidateServicePackage(packageName string, current map[string]openwrt.UCISection, desired []Section) error {
	wanted := make(map[string]Section, len(desired))
	for _, section := range desired {
		wanted[section.Name] = section
	}
	for name, section := range current {
		switch packageName {
		case "dhcp":
			if section.Type == "dnsmasq" && name != serviceDNSMasqSection {
				return fmt.Errorf("provider has an unowned dnsmasq instance %s", name)
			}
			if section.Type == "dhcp" && name != "boetticher_home" && !strings.HasPrefix(name, "boetticher_dhcp_") {
				if section.Options["ignore"] != "1" {
					return fmt.Errorf("provider has an active unowned DHCP scope %s", name)
				}
			}
		case "stubby":
			if section.Type == "resolver" {
				if _, ok := wanted[name]; !ok {
					return fmt.Errorf("provider has an unowned Stubby resolver %s", name)
				}
				if len(section.Lists["spki"]) > 0 {
					return fmt.Errorf("provider Stubby resolver %s contains an unsupported leaf certificate pin", name)
				}
			}
			if section.Type == "stubby" && name != serviceStubbyGlobal {
				return fmt.Errorf("provider has an unowned Stubby global section %s", name)
			}
		case "system":
			if section.Type == "timeserver" && name != serviceNTPSection && section.Options["enabled"] != "0" {
				return fmt.Errorf("provider has an active unowned time source %s", name)
			}
		}
	}
	return nil
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
	if normalized.DNS != nil {
		upstreams := normalized.DNS.Upstreams
		if len(upstreams) == 0 {
			upstreams = clientservices.DefaultDNSUpstreams()
		}
		// Infrastructure bindings are projected exactly once by dnsRecordSections;
		// persisted infrastructure intent must not create a second PTR owner.
		allRecords := append([]clientservices.DNSRecord(nil), normalized.DNS.Records...)
		generated, err := dnsRecordSections(site, allRecords)
		if err != nil {
			return ServiceState{}, err
		}
		state.DHCP = append(state.DHCP, generated...)
		state.Stubby = stubbySections(upstreams)
	}
	if normalized.Observability != nil && clientservices.ValidPublicDomain(normalized.Observability.PublicDomain) {
		state.DHCP = append(state.DHCP, observabilityDNSSections(normalized.Observability.PublicDomain)...)
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
	state.System = append(state.System, ntpSections(site, ntpUpstreams, ntpServe)...)
	vpnEnabled := normalized.VPN != nil && clientservices.Enabled(normalized.VPN.Enabled)
	state.Firewall = serviceFirewallSections(site, dnsEnabled, dhcpEnabled, vpnEnabled)
	observabilityFirewall, err := observabilityFirewallSections(site, normalized)
	if err != nil {
		return ServiceState{}, err
	}
	state.Firewall = append(state.Firewall, observabilityFirewall...)
	return state, nil
}

const (
	observabilityControllerExporterRule = "boetticher_observability_controller_exporter"
	observabilityHostExporterRule       = "boetticher_observability_host_exporter"
	observabilityControllerIngressRule  = "boetticher_observability_controller_ingress"
	observabilityHostIngressRule        = "boetticher_observability_host_ingress"
	observabilityRuntimeIngressRule     = "boetticher_observability_runtime_ingress"
	observabilityTrustedIngressRule     = "boetticher_observability_trusted_ingress"
	observabilityTailnetIngressRule     = "boetticher_observability_tailnet_ingress"
)

func observabilityFirewallSections(site model.Site, modules clientservices.Modules) ([]Section, error) {
	if modules.Observability == nil || !clientservices.Enabled(modules.Observability.Enabled) {
		return nil, nil
	}
	b := modules.Observability.Collection
	if b.Controller == "" || b.ProxmoxHost == "" || b.Runtime == "" {
		return nil, errors.New("enabled observability requires complete collection bindings")
	}
	roles := []struct {
		name, address, zone string
	}{
		{"controller", b.Controller, "SERVERS"},
		{"proxmox host", b.ProxmoxHost, "MGMT"},
		{"runtime", b.Runtime, "INFRA"},
	}
	for _, role := range roles {
		address, err := netip.ParseAddr(role.address)
		zone, ok := zoneByName(site, role.zone)
		if !ok {
			return nil, fmt.Errorf("%s zone is required for observability firewall projection", role.zone)
		}
		prefix, prefixErr := netip.ParsePrefix(zone.Network)
		if err != nil || !address.Is4() || prefixErr != nil || !prefix.Contains(address) {
			return nil, fmt.Errorf("observability %s binding is outside %s", role.name, role.zone)
		}
	}
	address := func(value string) string { return value + "/32" }
	rule := func(name, src, srcIP, dest, destIP, port string) Section {
		return Section{Name: name, Type: "rule", Options: map[string]string{
			"name": "Boetticher Observability " + name[len("boetticher_observability_"):], "src": src, "src_ip": srcIP,
			"dest": dest, "dest_ip": destIP, "proto": "tcp", "dest_port": port, "family": "ipv4", "target": "ACCEPT",
		}, Lists: map[string][]string{}}
	}
	sections := []Section{
		rule(observabilityControllerExporterRule, "infra", address(b.Runtime), "servers", address(b.Controller), "9100"),
		rule(observabilityHostExporterRule, "infra", address(b.Runtime), "mgmt", address(b.ProxmoxHost), "9100"),
		rule(observabilityControllerIngressRule, "servers", address(b.Controller), "infra", address(b.Runtime), "443"),
		rule(observabilityHostIngressRule, "mgmt", address(b.ProxmoxHost), "infra", address(b.Runtime), "443"),
		rule(observabilityRuntimeIngressRule, "infra", address(b.Runtime), "infra", address(b.Runtime), "443"),
	}
	trusted, ok := zoneByName(site, "TRUSTED")
	if !ok {
		return nil, errors.New("TRUSTED zone is required for observability firewall projection")
	}
	sections = append(sections, rule(observabilityTrustedIngressRule, "trusted", trusted.Network, "infra", address(b.Runtime), "443"))
	if modules.Tailnet != nil && modules.Tailnet.Enabled && hasExactTailnetReservation(modules) {
		sections = append(sections, rule(observabilityTailnetIngressRule, "transit", address(tailnet.GuestAddress), "infra", address(b.Runtime), "443"))
		sections[len(sections)-1].Options["src_mac"] = tailnet.GuestMAC
	}
	return sections, nil
}

func hasExactTailnetReservation(modules clientservices.Modules) bool {
	if modules.DHCP == nil {
		return false
	}
	for _, reservation := range modules.DHCP.Reservations {
		if reservation.Name == tailnet.GuestName && reservation.Zone == "TRANSIT" && strings.EqualFold(reservation.MAC, tailnet.GuestMAC) && reservation.Address == tailnet.GuestAddress {
			return true
		}
	}
	return false
}

func observabilityDNSSections(publicDomain string) []Section {
	names := []string{"observability", "status", "ingest", "metrics"}
	sections := make([]Section, 0, len(names))
	for _, name := range names {
		fqdn := name + "." + publicDomain
		sections = append(sections, Section{Name: "boetticher_observability_record_" + nativeRecordSuffix(fqdn), Type: "hostrecord", Options: map[string]string{"name": fqdn, "ip": "10.10.10.20"}, Lists: map[string][]string{}})
	}
	return sections
}

func dnsmasqSections(site model.Site, modules clientservices.Modules) []Section {
	dnsEnabled := modules.DNS != nil && clientservices.Enabled(modules.DNS.Enabled)
	dhcpEnabled := modules.DHCP != nil && clientservices.Enabled(modules.DHCP.Enabled)
	options := map[string]string{
		"disabled":          "1",
		"port":              "0",
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
		options["disabled"] = "0"
		options["local"] = "/" + site.Network.Domain + "/"
		lists["server"] = []string{clientservices.StubbyListenAddress}
		options["port"] = "53"
		for _, zone := range site.Network.Zones {
			lists["interface"] = append(lists["interface"], "boetticher_iface_"+strings.ToLower(zone.Name))
		}
		if dhcpEnabled {
			options["extraconftext"] = "dhcp-ignore-names=tag:boetticher_sandbox"
		}
	}
	if dhcpEnabled {
		options["disabled"] = "0"
		options["port"] = "53"
	}
	sections := []Section{{Name: serviceDNSMasqSection, Type: "dnsmasq", Options: options, Lists: lists}}
	sections = append(sections, Section{Name: "boetticher_home", Type: "dhcp", Options: map[string]string{
		"interface": "boetticher_home",
		"ignore":    "1",
		"ra":        "disabled",
		"dhcpv6":    "disabled",
		"ndp":       "disabled",
	}, Lists: map[string][]string{}})
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
			"interface": "boetticher_iface_" + name,
			"leasetime": modules.DHCP.LeaseDuration,
			// A static-only dnsmasq range still needs a valid subnet range;
			// dynamicdhcp=0 prevents unreserved clients from receiving leases.
			"start":       "2",
			"limit":       "253",
			"dynamicdhcp": "0",
			"force":       "1",
		}
		lists := map[string][]string{
			"dhcp_option": {
				"3," + zone.Gateway,
				// RFC 3442 option 121 clients ignore option 3, so include
				// both the LAB aggregate and the ordinary default route.
				"121,10.10.0.0/16," + zone.Gateway + ",0.0.0.0/0," + zone.Gateway,
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
			if zone.Type == model.ZoneTypeSandbox {
				// networkid emits set:<tag> on the range; tag:<tag> would
				// select only already-tagged packets and leave the range
				// unavailable to ordinary sandbox clients.
				options["networkid"] = "boetticher_sandbox"
			}
		}
		sections = append(sections, Section{Name: "boetticher_dhcp_" + name, Type: "dhcp", Options: options, Lists: lists})
	}
	for _, reservation := range modules.DHCP.Reservations {
		name := strings.ToLower(reservation.Name)
		sections = append(sections, Section{Name: nativeHostSectionName(name), Type: "host", Options: map[string]string{"name": name, "mac": reservation.MAC, "ip": reservation.Address, "dns": "1"}, Lists: map[string][]string{}})
	}
	return sections
}

func nativeHostSectionName(name string) string {
	return "boetticher_host_" + nativeIdentifier(name)
}

func nativeIdentifier(name string) string {
	var result strings.Builder
	for _, character := range name {
		switch {
		case character >= 'a' && character <= 'z', character >= 'A' && character <= 'Z', character >= '0' && character <= '9':
			result.WriteRune(character)
		case character == '_':
			result.WriteString("_u")
		case character == '-':
			result.WriteString("_h")
		case character == '.':
			result.WriteString("_d")
		default:
			result.WriteString("_x")
		}
	}
	return result.String()
}

func dnsRecordSections(site model.Site, records []clientservices.DNSRecord) ([]Section, error) {
	sections := make([]Section, 0, len(records))
	// Native dnsmasq host-record entries publish both A and reverse data. Keep
	// the canonical name as the only reverse owner; aliases are CNAMEs so two
	// names sharing an address cannot create competing PTR answers.
	bindingSections, err := bindingDNSSections(site)
	if err != nil {
		return nil, err
	}
	sections = append(sections, bindingSections...)
	ownedNames := map[string]struct{}{}
	ownedAddresses := map[string]string{}
	for _, section := range bindingSections {
		if name := section.Options["name"]; name != "" {
			ownedNames[name] = struct{}{}
		}
		if name := section.Options["cname"]; name != "" {
			ownedNames[name] = struct{}{}
		}
		if section.Type == "hostrecord" {
			ownedAddresses[section.Options["ip"]] = section.Options["name"]
		}
	}
	for _, record := range records {
		name, err := clientservices.CanonicalName(record.Name, site.Network.Domain)
		if err != nil {
			continue
		}
		if _, exists := ownedNames[name]; exists {
			return nil, fmt.Errorf("user DNS record %s collides with infrastructure-owned name", name)
		}
		safe := strings.TrimPrefix(nativeRecordSectionName(name), "boetticher_record_")
		switch record.Type {
		case "A":
			if canonical := net.ParseIP(record.Value); canonical != nil && canonical.To4() != nil {
				if owner, exists := ownedAddresses[canonical.To4().String()]; exists {
					return nil, fmt.Errorf("user DNS A record %s collides with infrastructure address %s owned by %s; use a CNAME alias", name, canonical, owner)
				}
			}
			sections = append(sections, Section{Name: "boetticher_record_" + safe, Type: "hostrecord", Options: map[string]string{"name": name, "ip": record.Value}, Lists: map[string][]string{}})
		case "CNAME":
			target, targetErr := clientservices.CanonicalName(record.Value, site.Network.Domain)
			if targetErr != nil {
				continue
			}
			sections = append(sections, Section{Name: "boetticher_cname_" + nativeRecordSuffix(strings.TrimSuffix(name, ".")), Type: "cname", Options: map[string]string{"cname": name, "target": target}, Lists: map[string][]string{}})
		}
	}
	return sections, nil
}

// bindingDNSSections projects the typed platform and network bindings into
// native dnsmasq records. The ordering is the PTR ownership policy: a
// platform component wins over a zone gateway, and a zone gateway wins over
// a later alias. No observed address or fixed lab address is consulted.
type dnsBinding struct {
	name    string
	ip      string
	role    int
	aliases []string
}

func bindingDNSSections(site model.Site) ([]Section, error) {
	bindings := make([]dnsBinding, 0, len(site.Components)+len(site.Network.Zones)+1)
	for _, component := range site.Components {
		if strings.TrimSpace(component.Hostname) == "" || strings.TrimSpace(component.Address) == "" {
			continue
		}
		if ip := net.ParseIP(component.Address); ip == nil || ip.To4() == nil || ip.To4().String() != component.Address {
			return nil, fmt.Errorf("infrastructure DNS binding %q has malformed IPv4 address %q", component.Hostname, component.Address)
		}
		bindings = append(bindings, dnsBinding{name: component.Hostname, ip: component.Address, role: 0, aliases: append([]string(nil), component.DNSAliases...)})
	}
	for _, zone := range site.Network.Zones {
		if strings.TrimSpace(zone.Name) == "" || strings.TrimSpace(zone.Gateway) == "" {
			continue
		}
		if ip := net.ParseIP(zone.Gateway); ip == nil || ip.To4() == nil || ip.To4().String() != zone.Gateway {
			return nil, fmt.Errorf("infrastructure DNS binding for zone %q has malformed IPv4 gateway %q", zone.Name, zone.Gateway)
		}
		bindings = append(bindings, dnsBinding{name: strings.ToLower(zone.Name) + "-gateway", ip: zone.Gateway, role: 1})
	}
	// The HOME address is an explicit gateway binding and remains outside LAB
	// DHCP, but its local name is still useful to clients on configured zones.
	if ip := net.ParseIP(site.Gateway.ManagementAddress); ip != nil && ip.To4() != nil && ip.To4().String() == site.Gateway.ManagementAddress {
		bindings = append(bindings, dnsBinding{name: "home-gateway", ip: site.Gateway.ManagementAddress, role: 2})
	}
	sort.SliceStable(bindings, func(i, j int) bool {
		if bindings[i].role != bindings[j].role {
			return bindings[i].role < bindings[j].role
		}
		if bindings[i].ip != bindings[j].ip {
			return bindings[i].ip < bindings[j].ip
		}
		return bindings[i].name < bindings[j].name
	})
	sections := make([]Section, 0, len(bindings))
	seenName := map[string]string{}
	seenAddress := map[string]struct{}{}
	for _, item := range bindings {
		name, err := clientservices.CanonicalName(item.name, site.Network.Domain)
		if err != nil {
			continue
		}
		if previous, exists := seenName[name]; exists {
			if previous != item.ip {
				return nil, fmt.Errorf("infrastructure DNS name %s collides between %s and %s", name, previous, item.ip)
			}
			continue
		}
		seenName[name] = item.ip
		if _, exists := seenAddress[item.ip]; exists {
			// A second canonical name for an address is represented as an alias
			// only when it has a distinct name, preserving one PTR owner.
			sections = append(sections, Section{Name: "boetticher_binding_cname_" + nativeRecordSuffix(strings.TrimSuffix(name, ".")), Type: "cname", Options: map[string]string{"cname": name, "target": canonicalBindingTarget(item.ip, bindings, site.Network.Domain)}, Lists: map[string][]string{}})
			continue
		}
		seenAddress[item.ip] = struct{}{}
		sections = append(sections, Section{Name: "boetticher_binding_record_" + nativeRecordSuffix(strings.TrimSuffix(name, ".")), Type: "hostrecord", Options: map[string]string{"name": name, "ip": item.ip}, Lists: map[string][]string{}})
		for _, alias := range item.aliases {
			aliasName, aliasErr := clientservices.CanonicalName(alias, site.Network.Domain)
			if aliasErr != nil || aliasName == name {
				continue
			}
			if previous, exists := seenName[aliasName]; exists {
				if previous != item.ip {
					return nil, fmt.Errorf("infrastructure DNS alias %s collides between %s and %s", aliasName, previous, item.ip)
				}
				continue
			}
			seenName[aliasName] = item.ip
			sections = append(sections, Section{Name: "boetticher_binding_cname_" + nativeRecordSuffix(strings.TrimSuffix(aliasName, ".")), Type: "cname", Options: map[string]string{"cname": aliasName, "target": name}, Lists: map[string][]string{}})
		}
	}
	return sections, nil
}

// InfrastructureDNSRecords returns the deterministic, typed desired state
// suitable for persisting in the canonical site model before an approved
// apply. Owner is stable and lets reconciliation remove only prior generated
// entries when a binding changes.
func InfrastructureDNSRecords(site model.Site) ([]model.DNSRecord, error) {
	sections, err := bindingDNSSections(site)
	if err != nil {
		return nil, err
	}
	result := make([]model.DNSRecord, 0, len(sections))
	for _, section := range sections {
		switch section.Type {
		case "hostrecord":
			result = append(result, model.DNSRecord{Name: section.Options["name"], Type: "A", Address: section.Options["ip"], Owner: "infrastructure"})
		case "cname":
			result = append(result, model.DNSRecord{Name: section.Options["cname"], Type: "CNAME", Address: section.Options["target"], Owner: "infrastructure"})
		}
	}
	return result, nil
}

func canonicalBindingTarget(ip string, bindings []dnsBinding, domain string) string {
	for _, item := range bindings {
		if item.ip == ip {
			if name, err := clientservices.CanonicalName(item.name, domain); err == nil {
				return name
			}
		}
	}
	return ""
}

func nativeRecordSuffix(name string) string {
	var result strings.Builder
	result.WriteString("n")
	for _, character := range name {
		switch {
		case character >= 'a' && character <= 'z', character >= '0' && character <= '9':
			result.WriteRune(character)
		case character == '-':
			result.WriteString("_h")
		case character == '.':
			result.WriteString("_d")
		default:
			result.WriteString("_x")
		}
	}
	return result.String()
}

func stubbySections(upstreams []clientservices.DNSUpstream) []Section {
	sections := []Section{{Name: serviceStubbyGlobal, Type: "stubby", Options: map[string]string{
		"manual":                      "0",
		"trigger":                     "boetticher_home",
		"tls_authentication":          "1",
		"tls_min_version":             "1.2",
		"edns_client_subnet_private":  "1",
		"round_robin_upstreams":       "1",
		"appdata_dir":                 "/var/lib/stubby",
		"tls_query_padding_blocksize": "128",
		"idle_timeout":                "10000",
	}, Lists: map[string][]string{"listen_address": {"127.0.0.1@5453"}, "dns_transport": {"GETDNS_TRANSPORT_TLS"}}}}
	for _, upstream := range upstreams {
		safe := strings.TrimPrefix(nativeResolverSectionName(upstream.Address), "boetticher_resolver_")
		sections = append(sections, Section{Name: "boetticher_resolver_" + safe, Type: "resolver", Options: map[string]string{
			"address":       upstream.Address,
			"tls_auth_name": upstream.TLSName,
			"tls_port":      strconv.Itoa(upstream.Port),
		}, Lists: map[string][]string{}})
	}
	return sections
}

func ntpSections(site model.Site, upstreams []string, serve *bool) []Section {
	enableServer := "0"
	if serve != nil && *serve {
		enableServer = "1"
	}
	_ = site // BusyBox sysntpd does not consume an interface UCI option; firewall input scopes the server.
	return []Section{{Name: serviceNTPSection, Type: "timeserver", Options: map[string]string{"enabled": "1", "use_dhcp": "0", "enable_server": enableServer}, Lists: map[string][]string{"server": append([]string(nil), upstreams...)}}}
}

func serviceFirewallSections(site model.Site, dnsEnabled, dhcpEnabled, vpnEnabled bool) []Section {
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
				if vpnEnabled {
					sections = append(sections, Section{Name: "boetticher_deny_" + name + "_external_" + item.suffix + "_vpn", Type: "rule", Options: map[string]string{"name": "Boetticher " + zone.Name + " deny external " + item.suffix + " via VPN", "src": name, "dest": "vpn", "proto": item.protocol, "dest_port": item.port, "family": "ipv4", "target": "DROP"}, Lists: map[string][]string{}})
				}
			}
		}
		if dhcpEnabled {
			sections = append(sections, Section{Name: "boetticher_allow_" + name + "_ntp", Type: "rule", Options: map[string]string{"name": "Boetticher " + zone.Name + " NTP", "src": name, "proto": "udp", "dest_port": "123", "family": "ipv4", "target": "ACCEPT"}, Lists: map[string][]string{}})
			sections = append(sections, Section{Name: "boetticher_deny_" + name + "_external_ntp", Type: "rule", Options: map[string]string{"name": "Boetticher " + zone.Name + " deny external NTP", "src": name, "dest": "home_wan", "proto": "udp", "dest_port": "123", "family": "ipv4", "target": "DROP"}, Lists: map[string][]string{}})
			if vpnEnabled {
				sections = append(sections, Section{Name: "boetticher_deny_" + name + "_external_ntp_vpn", Type: "rule", Options: map[string]string{"name": "Boetticher " + zone.Name + " deny external NTP via VPN", "src": name, "dest": "vpn", "proto": "udp", "dest_port": "123", "family": "ipv4", "target": "DROP"}, Lists: map[string][]string{}})
			}
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
