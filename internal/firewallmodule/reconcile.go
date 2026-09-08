package firewallmodule

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/gofastercloud/boetticher/internal/openwrt"
	"github.com/gofastercloud/boetticher/internal/tailnet"
)

type MutationKind string

const (
	MutationCreate MutationKind = "create"
	MutationUpdate MutationKind = "update"
	MutationDelete MutationKind = "delete"
)

type Mutation struct {
	Kind    MutationKind
	Section Section
}

// DiffOwned computes the minimal mutations for one UCI package. Only named
// boetticher sections are considered; unrelated provider-native sections are
// deliberately absent from the result.
func DiffOwned(current map[string]openwrt.UCISection, desired []Section) ([]Mutation, error) {
	wanted := make(map[string]Section, len(desired))
	for _, section := range desired {
		wanted[section.Name] = section
	}
	mutations := make([]Mutation, 0)
	for _, name := range sortedSectionNames(desired) {
		section := wanted[name]
		observed, exists := current[name]
		if !exists {
			mutations = append(mutations, Mutation{Kind: MutationCreate, Section: section})
			continue
		}
		if observed.Type != section.Type {
			return nil, fmt.Errorf("provider section %s has conflicting type %q, expected %q", name, observed.Type, section.Type)
		}
		if !compatibleIdentity(name, observed, section) {
			return nil, fmt.Errorf("provider section %s has conflicting managed identity", name)
		}
		if !sameSection(observed, section) {
			mutations = append(mutations, Mutation{Kind: MutationUpdate, Section: section})
		}
	}
	stale := make([]string, 0)
	for name := range current {
		if _, exists := wanted[name]; !exists && managedStaleSection(name, current[name]) {
			stale = append(stale, name)
		}
	}
	sort.Strings(stale)
	for _, name := range stale {
		mutations = append(mutations, Mutation{Kind: MutationDelete, Section: Section{Name: name}})
	}
	return mutations, nil
}

func managedStaleSection(name string, section openwrt.UCISection) bool {
	if managedVPNFirewallSection(name, section) {
		return true
	}
	if name == "airvpn" && section.Type == "interface" {
		return true
	}
	if strings.HasPrefix(name, "boetticher_vpn_") {
		switch section.Type {
		case "interface", "wireguard_airvpn", "route", "rule", "zone", "forwarding", "redirect":
			return true
		}
	}
	if section.Type == "host" {
		return nativeHostSectionName(section.Options["name"]) == name && section.Options["name"] != ""
	}
	if section.Type == "dhcp" && strings.HasPrefix(name, "boetticher_dhcp_") {
		for _, zone := range []string{"transit", "infrastructure", "servers", "trusted", "sandbox", "management", "mgmt"} {
			if name == "boetticher_dhcp_"+zone {
				return true
			}
		}
	}
	if section.Type == "resolver" && strings.HasPrefix(name, "boetticher_resolver_") {
		return nativeResolverSectionName(section.Options["address"]) == name && section.Options["address"] != ""
	}
	if section.Type == "hostrecord" && strings.HasPrefix(name, "boetticher_record_") {
		return nativeRecordSectionName(section.Options["name"]) == name && section.Options["name"] != ""
	}
	if section.Type == "cname" && strings.HasPrefix(name, "boetticher_cname_") {
		return "boetticher_cname_"+nativeRecordSuffix(strings.TrimSuffix(section.Options["cname"], ".")) == name && section.Options["cname"] != ""
	}
	if section.Type == "rule" {
		return managedRuleIdentity(name, section.Options)
	}
	if section.Type == "forwarding" && strings.HasPrefix(name, "boetticher_forward_") {
		pairs := map[string][2]string{"boetticher_forward_trusted_servers": {"trusted", "servers"}}
		for _, zone := range []string{"transit", "infra", "servers", "trusted", "sandbox", "mgmt"} {
			pairs["boetticher_forward_"+zone+"_home_wan"] = [2]string{zone, "home_wan"}
		}
		if pair, ok := pairs[name]; ok {
			return section.Options["src"] == pair[0] && section.Options["dest"] == pair[1] && section.Options["family"] == "ipv4"
		}
	}
	return false
}

func managedRuleIdentity(name string, options map[string]string) bool {
	if strings.HasPrefix(name, "boetticher_tailnet_") {
		id := strings.TrimPrefix(name, "boetticher_tailnet_")
		expectedName, ok := map[string]string{
			"deny_home":      "Boetticher Tailnet deny_home",
			"deny_nonpublic": "Boetticher Tailnet deny_nonpublic",
			"transport_tcp":  "Boetticher Tailnet transport_tcp",
			"transport_udp":  "Boetticher Tailnet transport_udp",
			"dns":            "Boetticher Tailnet dns",
			"ntp":            "Boetticher Tailnet ntp",
			"trusted":        "Boetticher Tailnet trusted",
			"servers":        "Boetticher Tailnet servers",
		}[id]
		return ok && options["name"] == expectedName && options["src"] == "transit" && options["src_ip"] == tailnet.GuestAddress+"/32" && options["src_mac"] == tailnet.GuestMAC && options["family"] == "ipv4"
	}
	zones := map[string]string{"transit": "TRANSIT", "infra": "INFRA", "servers": "SERVERS", "trusted": "TRUSTED", "sandbox": "SANDBOX", "mgmt": "MGMT"}
	for zone, label := range zones {
		checks := map[string][3]string{
			"boetticher_allow_" + zone + "_ping":         {"Boetticher " + label + " gateway ping", zone, "icmp"},
			"boetticher_allow_" + zone + "_dhcp":         {"Boetticher " + label + " DHCP", zone, "udp"},
			"boetticher_deny_" + zone + "_external_dhcp": {"Boetticher " + label + " deny external DHCP", zone, "udp"},
			"boetticher_allow_" + zone + "_ntp":          {"Boetticher " + label + " NTP", zone, "udp"},
			"boetticher_deny_" + zone + "_external_ntp":  {"Boetticher " + label + " deny external NTP", zone, "udp"},
		}
		for _, protocol := range []string{"tcp", "udp"} {
			checks["boetticher_allow_"+zone+"_dns_"+protocol] = [3]string{"Boetticher " + label + " DNS " + protocol, zone, protocol}
		}
		for _, item := range []struct{ suffix, proto, port string }{{"dns_udp", "udp", "53"}, {"dns_tcp", "tcp", "53"}, {"dot_tcp", "tcp", "853"}} {
			checks["boetticher_deny_"+zone+"_external_"+item.suffix] = [3]string{"Boetticher " + label + " deny external " + item.suffix, zone, item.proto}
			checks["boetticher_deny_"+zone+"_external_"+item.suffix+"_vpn"] = [3]string{"Boetticher " + label + " deny external " + item.suffix + " via VPN", zone, item.proto}
		}
		checks["boetticher_deny_"+zone+"_external_ntp_vpn"] = [3]string{"Boetticher " + label + " deny external NTP via VPN", zone, "udp"}
		if expected, ok := checks[name]; ok {
			return options["name"] == expected[0] && options["src"] == expected[1] && options["proto"] == expected[2] && options["family"] == "ipv4"
		}
	}
	return name == "boetticher_allow_home_api" && options["name"] == "Boetticher Controller management API" && options["src"] == "home_wan" && options["proto"] == "tcp" && options["family"] == "ipv4"
}

func compatibleIdentity(name string, observed openwrt.UCISection, desired Section) bool {
	if name == "airvpn" {
		return observed.Options["proto"] == "wireguard"
	}
	if observed.Type == "host" {
		return observed.Options["name"] == desired.Options["name"]
	}
	if observed.Type == "hostrecord" || observed.Type == "cname" || observed.Type == "resolver" {
		key := "name"
		if observed.Type == "cname" {
			key = "cname"
		}
		return observed.Options[key] == desired.Options[key]
	}
	if observed.Type == "rule" || observed.Type == "forwarding" {
		if observed.Type == "rule" && strings.HasPrefix(name, "boetticher_tailnet_") {
			return managedRuleIdentity(name, observed.Options)
		}
		if !managedStaleSection(name, observed) {
			return true
		}
		return managedStaleSection(name, observed)
	}
	return true
}

func nativeResolverSectionName(address string) string {
	return "boetticher_resolver_" + strings.ReplaceAll(address, ".", "_")
}

func nativeRecordSectionName(name string) string {
	return "boetticher_record_" + nativeRecordSuffix(strings.TrimSuffix(name, "."))
}

func sameSection(observed openwrt.UCISection, desired Section) bool {
	if observed.Type != desired.Type || len(observed.Options) != len(desired.Options) {
		return false
	}
	for key, value := range desired.Options {
		if observed.Options[key] != value {
			return false
		}
	}
	for key, values := range desired.Lists {
		observedValues, exists := observed.Lists[key]
		if len(values) == 0 && (!exists || len(observedValues) == 0) {
			continue
		}
		if len(observedValues) != len(values) {
			return false
		}
		for index := range values {
			if observedValues[index] != values[index] {
				return false
			}
		}
	}
	for key, values := range observed.Lists {
		if _, wanted := desired.Lists[key]; !wanted && len(values) != 0 {
			return false
		}
	}
	return true
}

type uciWriter interface {
	UCIAddNamed(context.Context, string, string, string) (string, error)
	UCISet(context.Context, string, string, string, string) error
	UCISetList(context.Context, string, string, string, []string) error
	UCIDelete(context.Context, string, string, string) error
	UCIApply(context.Context, int) error
}

// ReconcileOwned applies one package's named sections and returns the number
// of semantic changes. It does not touch any unowned section.
func ReconcileOwned(ctx context.Context, client uciWriter, packageName string, current map[string]openwrt.UCISection, desired []Section) (int, error) {
	if packageName == "firewall" {
		current = FirewallScope(current, desired)
	}
	if client == nil {
		return 0, errors.New("provider UCI client is required")
	}
	_, err := DiffOwned(current, desired)
	if err != nil {
		return 0, err
	}
	changed, err := StageOwned(ctx, client, packageName, current, desired)
	if err != nil || changed == 0 {
		return changed, err
	}
	if err := client.UCIApply(ctx, 30); err != nil {
		return 0, err
	}
	return changed, nil
}

// StageOwned writes UCI changes without activation.
func StageOwned(ctx context.Context, client uciWriter, packageName string, current map[string]openwrt.UCISection, desired []Section) (int, error) {
	if client == nil {
		return 0, errors.New("provider UCI client is required")
	}
	if packageName == "firewall" {
		current = FirewallScope(current, desired)
	}
	mutations, err := DiffOwned(current, desired)
	if err != nil {
		return 0, err
	}
	for _, mutation := range mutations {
		section := mutation.Section
		switch mutation.Kind {
		case MutationCreate:
			created, err := client.UCIAddNamed(ctx, packageName, section.Type, section.Name)
			if err != nil {
				return 0, fmt.Errorf("create provider section %s: %w", section.Name, err)
			}
			if created != section.Name {
				return 0, fmt.Errorf("create provider section %s returned unexpected name %q", section.Name, created)
			}
			if err := writeSection(ctx, client, packageName, section, nil); err != nil {
				return 0, err
			}
		case MutationUpdate:
			observed := current[section.Name]
			if err := writeSection(ctx, client, packageName, section, &observed); err != nil {
				return 0, err
			}
		case MutationDelete:
			if err := client.UCIDelete(ctx, packageName, section.Name, ""); err != nil {
				return 0, fmt.Errorf("delete stale provider section %s: %w", section.Name, err)
			}
		default:
			return 0, fmt.Errorf("unsupported provider mutation %q", mutation.Kind)
		}
	}
	return len(mutations), nil
}

func writeSection(ctx context.Context, client uciWriter, packageName string, desired Section, observed *openwrt.UCISection) error {
	if observed != nil && observed.Type != desired.Type {
		return fmt.Errorf("provider section %s has type %q, expected %q", desired.Name, observed.Type, desired.Type)
	}
	if observed != nil {
		for option := range observed.Options {
			if _, keep := desired.Options[option]; !keep {
				if err := client.UCIDelete(ctx, packageName, desired.Name, option); err != nil {
					return fmt.Errorf("remove stale provider option %s.%s: %w", desired.Name, option, err)
				}
			}
		}
		for list := range observed.Lists {
			if _, keep := desired.Lists[list]; !keep {
				if err := client.UCIDelete(ctx, packageName, desired.Name, list); err != nil {
					return fmt.Errorf("remove stale provider list %s.%s: %w", desired.Name, list, err)
				}
			}
		}
	}
	optionNames := make([]string, 0, len(desired.Options))
	for option := range desired.Options {
		optionNames = append(optionNames, option)
	}
	sort.Strings(optionNames)
	for _, option := range optionNames {
		if observed != nil && observed.Options[option] == desired.Options[option] {
			continue
		}
		if err := client.UCISet(ctx, packageName, desired.Name, option, desired.Options[option]); err != nil {
			return fmt.Errorf("set provider option %s.%s: %w", desired.Name, option, err)
		}
	}
	listNames := make([]string, 0, len(desired.Lists))
	for list := range desired.Lists {
		listNames = append(listNames, list)
	}
	sort.Strings(listNames)
	for _, list := range listNames {
		values := desired.Lists[list]
		if observed != nil && sameStringSlice(observed.Lists[list], values) {
			continue
		}
		if observed != nil && len(observed.Lists[list]) > 0 {
			if err := client.UCIDelete(ctx, packageName, desired.Name, list); err != nil {
				return fmt.Errorf("reset provider list %s.%s: %w", desired.Name, list, err)
			}
		}
		if len(values) == 0 {
			continue
		}
		if err := client.UCISetList(ctx, packageName, desired.Name, list, values); err != nil {
			return fmt.Errorf("set provider list %s.%s: %w", desired.Name, list, err)
		}
	}
	return nil
}

func sameStringSlice(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
