package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
)

const (
	InternalBridge        = "vmbr1"
	HomeManagementAddress = "192.168.4.5"
)

type VLANConfig struct {
	Transit int `yaml:"transit"`
	Infra   int `yaml:"infra"`
	Servers int `yaml:"servers"`
	Trusted int `yaml:"trusted"`
	Sandbox int `yaml:"sandbox"`
	Mgmt    int `yaml:"mgmt"`
}

type NetworkConfig struct {
	InternalBridge   string           `yaml:"internal_bridge"`
	PhysicalTrunk    string           `yaml:"physical_trunk,omitempty"`
	PhysicalTrunkMAC string           `yaml:"physical_trunk_mac,omitempty"`
	VLANs            VLANConfig       `yaml:"vlans"`
	Domain           string           `yaml:"domain,omitempty"`
	ProtectedRanges  *ProtectedRanges `yaml:"protected_ranges,omitempty"`
}

// ProtectedRanges is persisted only after an explicit adoption. A nil block
// preserves legacy configurations and does not imply that ranges are free.
type ProtectedRanges struct {
	Infra   string `yaml:"infra,omitempty"`
	Servers string `yaml:"servers,omitempty"`
	Trusted string `yaml:"trusted,omitempty"`
	Sandbox string `yaml:"sandbox,omitempty"`
}

// ProtectedRangeObservations are read-only addresses supplied by callers.
// They are deliberately separated by source so a preparation decision can be
// audited without performing live reads here.
type ProtectedRangeObservations struct {
	Reservations       []string
	Leases             []string
	ManagedAttachments []string
}

// PrepareProtectedRangeChange validates adoption or retention of protected
// ranges. Existing ranges cannot be released or changed. A new range must be
// empty according to every supplied observation source.
func PrepareProtectedRangeChange(current, proposed *ProtectedRanges, observations ProtectedRangeObservations) error {
	if err := validateProtectedObservations(observations, nil); err != nil {
		return err
	}
	if proposed != nil {
		if proposed.Infra != "10.10.10.224/28" || proposed.Servers != "10.10.20.224/28" || proposed.Trusted != "10.10.30.224/28" || proposed.Sandbox != "10.10.40.224/28" {
			return errors.New("protected ranges must be the canonical reference .224/28 ranges")
		}
	}
	if proposed == nil {
		if current != nil {
			return errors.New("adopted protected ranges cannot be released")
		}
		return nil
	}
	if current != nil {
		if *current != *proposed {
			return errors.New("adopted protected ranges cannot be changed")
		}
		return nil
	}
	if err := validateProtectedObservations(observations, proposed); err != nil {
		return err
	}
	return nil
}

func validateProtectedObservations(observations ProtectedRangeObservations, proposed *ProtectedRanges) error {
	for source, values := range map[string][]string{"reservation": observations.Reservations, "lease": observations.Leases, "managed attachment": observations.ManagedAttachments} {
		for _, value := range values {
			address, err := netip.ParseAddr(value)
			if err != nil || !address.Is4() || address.String() != value {
				return fmt.Errorf("protected range %s observation %q must be canonical IPv4", source, value)
			}
			if proposed != nil {
				for zone, cidr := range map[string]string{"infra": proposed.Infra, "servers": proposed.Servers, "trusted": proposed.Trusted, "sandbox": proposed.Sandbox} {
					prefix, _ := netip.ParsePrefix(cidr)
					if prefix.Contains(address) {
						return fmt.Errorf("protected range %s is occupied by %s %s", zone, source, value)
					}
				}
			}
		}
	}
	return nil
}

type ManagementPath struct {
	Address      string
	Bridge       string
	EgressDevice string
	Gateway      string
	Members      []string
}

type BridgeState struct {
	Exists                  bool
	Up                      bool
	VLANAware               bool
	HostAddresses           []string
	Gateway                 string
	PhysicalMembers         []string
	PhysicalEthernetMembers []string
	ManagementAddress       bool
	ManagementRoutes        bool
	ManagementOwned         bool
	ManagementIPv6Disabled  bool
	TrunkMatches            bool
	Configured              bool
	Adoptable               bool
	IPv6Disabled            bool
	Owned                   bool
	Detail                  string
}

type NetworkPlan struct {
	Management ManagementPath
	Bridge     BridgeState
	Config     NetworkConfig
	State      string
	Detail     string
	Links      json.RawMessage
	Addresses  json.RawMessage
	Routes     json.RawMessage
}

func DefaultNetworkConfig() NetworkConfig {
	return NetworkConfig{InternalBridge: InternalBridge, VLANs: VLANConfig{Transit: 5, Infra: 10, Servers: 20, Trusted: 30, Sandbox: 40, Mgmt: 99}, Domain: model.DefaultDomain}
}

func ValidateNetworkConfig(config NetworkConfig) error {
	if config.InternalBridge != InternalBridge {
		return fmt.Errorf("internal bridge must be %s", InternalBridge)
	}
	if config.Domain != "" && config.Domain != model.DefaultDomain {
		return fmt.Errorf("network domain must be %s", model.DefaultDomain)
	}
	if config.PhysicalTrunk != "" && !safeIdentifier(config.PhysicalTrunk) {
		return errors.New("network physical trunk must be a safe interface name")
	}
	if (config.PhysicalTrunk == "") != (config.PhysicalTrunkMAC == "") {
		return errors.New("network physical trunk requires both interface name and permanent MAC")
	}
	if config.PhysicalTrunkMAC != "" {
		if mac, err := net.ParseMAC(config.PhysicalTrunkMAC); err != nil || len(mac) != 6 {
			return errors.New("network physical trunk MAC must be an Ethernet MAC")
		}
	}
	values := []int{config.VLANs.Transit, config.VLANs.Infra, config.VLANs.Servers, config.VLANs.Trusted, config.VLANs.Sandbox, config.VLANs.Mgmt}
	seen := map[int]bool{}
	for _, value := range values {
		if value < 1 || value > 4094 || seen[value] {
			return errors.New("network VLAN IDs must be unique values from 1 through 4094")
		}
		seen[value] = true
	}
	if config.ProtectedRanges != nil {
		for zone, value := range map[string]string{"infra": config.ProtectedRanges.Infra, "servers": config.ProtectedRanges.Servers, "trusted": config.ProtectedRanges.Trusted, "sandbox": config.ProtectedRanges.Sandbox} {
			if value == "" {
				return fmt.Errorf("network protected range %s is required", zone)
			}
			want := map[string]string{"infra": "10.10.10.224/28", "servers": "10.10.20.224/28", "trusted": "10.10.30.224/28", "sandbox": "10.10.40.224/28"}[zone]
			if value != want {
				return fmt.Errorf("network protected range %s must be canonical %s", zone, want)
			}
		}
	}
	return nil
}

// SelectPhysicalTrunk obtains the durable NIC identity immediately before the
// Host mutation path records it. The caller must still obtain normal apply
// confirmation; this function is read-only.
func SelectPhysicalTrunk(ctx context.Context, transport Transport, name string) (NetworkConfig, error) {
	if !safeIdentifier(name) {
		return NetworkConfig{}, errors.New("physical trunk must be a safe interface name")
	}
	result, err := transport.Run(ctx, "ip -json link show dev "+name)
	if err != nil {
		return NetworkConfig{}, fmt.Errorf("read selected physical trunk: %w", err)
	}
	var links []ipLink
	if err := json.Unmarshal(result.Stdout, &links); err != nil || len(links) != 1 || links[0].IfName != name || links[0].LinkType != "ether" || (links[0].Master != "" && links[0].Master != InternalBridge) {
		return NetworkConfig{}, errors.New("selected physical trunk is not an unused or vmbr1-attached Ethernet interface")
	}
	permanent, err := transport.Run(ctx, "ethtool -P "+name)
	if err != nil {
		return NetworkConfig{}, fmt.Errorf("read selected physical trunk permanent MAC: %w", err)
	}
	fields := strings.Fields(string(permanent.Stdout))
	if len(fields) < 3 || !strings.EqualFold(fields[0], "Permanent") || !strings.EqualFold(strings.TrimSuffix(fields[1], ":"), "address") {
		return NetworkConfig{}, errors.New("selected physical trunk permanent MAC is unavailable")
	}
	mac, err := net.ParseMAC(fields[2])
	if err != nil || len(mac) != 6 {
		return NetworkConfig{}, errors.New("selected physical trunk permanent MAC is invalid")
	}
	config := DefaultNetworkConfig()
	config.PhysicalTrunk, config.PhysicalTrunkMAC = name, strings.ToLower(mac.String())
	return config, nil
}

type ipLink struct {
	IfName    string   `json:"ifname"`
	LinkType  string   `json:"link_type"`
	Master    string   `json:"master"`
	OperState string   `json:"operstate"`
	Flags     []string `json:"flags"`
	Address   string   `json:"address"`
}

type ipAddress struct {
	IfName   string `json:"ifname"`
	AddrInfo []struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		Scope     string `json:"scope"`
		PrefixLen int    `json:"prefixlen"`
	} `json:"addr_info"`
}

type ipRoute struct {
	Dst     string `json:"dst"`
	Gateway string `json:"gateway"`
	Dev     string `json:"dev"`
}

func DiscoverNetwork(ctx context.Context, transport Transport, config LabConfig) (NetworkPlan, error) {
	if err := ValidateConfig(config); err != nil {
		return NetworkPlan{}, err
	}
	want := DefaultNetworkConfig()
	if config.Network != nil {
		want = *config.Network
	}
	if err := ValidateNetworkConfig(want); err != nil {
		return NetworkPlan{}, err
	}
	linksResult, err := transport.Run(ctx, "ip -json link")
	if err != nil {
		return NetworkPlan{}, fmt.Errorf("read Proxmox links: %w", err)
	}
	addressesResult, err := transport.Run(ctx, "ip -json address")
	if err != nil {
		return NetworkPlan{}, fmt.Errorf("read Proxmox addresses: %w", err)
	}
	routesResult, err := transport.Run(ctx, "ip -json route")
	if err != nil {
		return NetworkPlan{}, fmt.Errorf("read Proxmox routes: %w", err)
	}
	pathResult, err := transport.Run(ctx, "ip route get 192.168.4.6")
	if err != nil {
		return NetworkPlan{}, fmt.Errorf("read Controller return path: %w", err)
	}
	bridgeResult, err := transport.Run(ctx, "bridge link")
	if err != nil {
		return NetworkPlan{}, fmt.Errorf("read bridge membership: %w", err)
	}
	detailResult, err := transport.Run(ctx, "ip -d link show vmbr1 2>/dev/null || true")
	if err != nil {
		return NetworkPlan{}, fmt.Errorf("read vmbr1 state: %w", err)
	}
	configResult, err := transport.Run(ctx, `set -eu; names=$(ifquery --list); if printf '%s\n' "$names" | grep -qx vmbr1; then ifquery --raw vmbr1; fi`)
	if err != nil {
		return NetworkPlan{}, fmt.Errorf("read vmbr1 configuration: %w", err)
	}
	ipv6Result, err := transport.Run(ctx, `if [ -e /proc/sys/net/ipv6/conf/vmbr1/disable_ipv6 ]; then cat /proc/sys/net/ipv6/conf/vmbr1/disable_ipv6; fi`)
	if err != nil {
		return NetworkPlan{}, fmt.Errorf("read vmbr1 IPv6 state: %w", err)
	}
	trustedRouteResult, tailnetRouteResult, mgmtOwnedResult := Result{}, Result{}, Result{}
	if want.PhysicalTrunk != "" {
		trustedRouteResult, err = transport.Run(ctx, "ip -4 route get 10.10.30.1")
		if err != nil {
			return NetworkPlan{}, fmt.Errorf("read Proxmox TRUSTED return route: %w", err)
		}
		tailnetRouteResult, err = transport.Run(ctx, "ip -4 route get 10.10.5.10")
		if err != nil {
			return NetworkPlan{}, fmt.Errorf("read Proxmox Tailnet return route: %w", err)
		}
		mgmtOwnedResult, err = transport.Run(ctx, managementOwnershipCommand())
		if err != nil {
			return NetworkPlan{}, fmt.Errorf("read Proxmox MGMT ownership: %w", err)
		}
	}
	ownedResult, err := transport.Run(ctx, networkOwnershipCommand())
	if err != nil {
		return NetworkPlan{}, fmt.Errorf("read vmbr1 ownership: %w", err)
	}
	routes6Result, err := transport.Run(ctx, "ip -json -6 route")
	if err != nil {
		return NetworkPlan{}, fmt.Errorf("read IPv6 routes: %w", err)
	}
	var routes6 []ipRoute
	if err := json.Unmarshal(routes6Result.Stdout, &routes6); err != nil {
		return NetworkPlan{}, fmt.Errorf("decode IPv6 routes: %w", err)
	}
	var links []ipLink
	var addresses []ipAddress
	var routes []ipRoute
	if err := json.Unmarshal(linksResult.Stdout, &links); err != nil {
		return NetworkPlan{}, fmt.Errorf("decode Proxmox links: %w", err)
	}
	if err := json.Unmarshal(addressesResult.Stdout, &addresses); err != nil {
		return NetworkPlan{}, fmt.Errorf("decode Proxmox addresses: %w", err)
	}
	if err := json.Unmarshal(routesResult.Stdout, &routes); err != nil {
		return NetworkPlan{}, fmt.Errorf("decode Proxmox routes: %w", err)
	}
	management := managementPath(links, addresses, routes, string(pathResult.Stdout))
	bridge := bridgeState(links, addresses, append(routes, routes6...), string(bridgeResult.Stdout), string(detailResult.Stdout), string(configResult.Stdout))
	bridge.TrunkMatches = trunkMatches(want, links, configuredBridgePort(string(configResult.Stdout)))
	if bridge.Exists && ((want.PhysicalTrunk != "" && !bridge.TrunkMatches) || (want.PhysicalTrunk == "" && configuredBridgePort(string(configResult.Stdout)) != "none")) {
		bridge.Adoptable = false
		bridge.Detail = "vmbr1 physical trunk does not match the persisted Host binding"
	}
	bridge.ManagementAddress = hasIPv4Address(addresses, "vmbr1.99", "10.10.99.5")
	bridge.ManagementRoutes = routeUsesManagement(string(trustedRouteResult.Stdout)) && routeUsesManagement(string(tailnetRouteResult.Stdout))
	bridge.ManagementOwned = strings.TrimSpace(string(mgmtOwnedResult.Stdout)) == "owned"
	bridge.IPv6Disabled = strings.TrimSpace(string(ipv6Result.Stdout)) == "1"
	bridge.Owned = strings.TrimSpace(string(ownedResult.Stdout)) == "owned"
	plan := NetworkPlan{Management: management, Bridge: bridge, Config: want, Links: linksResult.Stdout, Addresses: addressesResult.Stdout, Routes: routesResult.Stdout}
	if management.Address != HomeManagementAddress || management.Bridge == "" || management.EgressDevice == "" || management.Gateway == "" || management.Bridge != management.EgressDevice || len(management.Members) == 0 {
		plan.State = "conflict"
		plan.Detail = "HOME management path is absent or ambiguous"
		return plan, nil
	}
	if !bridge.Exists && strings.TrimSpace(string(configResult.Stdout)) == "" {
		plan.State = "absent"
		plan.Detail = "vmbr1 is absent and can be created additively"
	} else if bridge.Up && bridge.VLANAware && len(bridge.HostAddresses) == 0 && bridge.Gateway == "" && bridge.Configured && bridge.Owned && bridge.IPv6Disabled && bridge.TrunkMatches && (want.PhysicalTrunk == "" || (bridge.ManagementAddress && bridge.ManagementRoutes && bridge.ManagementOwned)) {
		plan.State = "exact"
		plan.Detail = "vmbr1 is up with the expected VLAN-aware Host shape"
	} else if bridge.Adoptable {
		plan.State = "adoptable"
		plan.Detail = bridge.Detail
	} else {
		plan.State = "conflict"
		plan.Detail = bridge.Detail
	}
	return plan, nil
}

func hasIPv4Address(addresses []ipAddress, iface, value string) bool {
	for _, address := range addresses {
		if address.IfName != iface {
			continue
		}
		for _, info := range address.AddrInfo {
			if info.Family == "inet" && info.Local == value && info.PrefixLen == 24 {
				return true
			}
		}
	}
	return false
}

func managementPath(links []ipLink, addresses []ipAddress, routes []ipRoute, routeOutput string) ManagementPath {
	path := ManagementPath{Address: HomeManagementAddress}
	for _, address := range addresses {
		for _, info := range address.AddrInfo {
			if info.Family == "inet" && info.Local == path.Address {
				path.Bridge = address.IfName
			}
		}
	}
	fields := strings.Fields(routeOutput)
	for index, field := range fields {
		if field == "dev" && index+1 < len(fields) {
			path.EgressDevice = fields[index+1]
		}
		if field == "src" && index+1 < len(fields) && path.Address == "" {
			path.Address = fields[index+1]
		}
	}
	for _, route := range routes {
		if route.Dst == "default" {
			path.Gateway = route.Gateway
		}
	}
	for _, link := range links {
		if link.Master == path.Bridge && link.IfName != path.Bridge {
			path.Members = append(path.Members, link.IfName)
		}
	}
	return path
}

func bridgeState(links []ipLink, addresses []ipAddress, routes []ipRoute, membership, detail, config string) BridgeState {
	state := BridgeState{}
	linkLocalOnly := true
	for _, link := range links {
		if link.IfName == InternalBridge {
			state.Exists = true
			state.Up = link.OperState == "UP" || containsString(link.Flags, "UP")
		}
		if link.Master == InternalBridge && link.IfName != InternalBridge {
			state.PhysicalMembers = append(state.PhysicalMembers, link.IfName)
			if link.LinkType == "ether" {
				state.PhysicalEthernetMembers = append(state.PhysicalEthernetMembers, link.IfName)
			}
		}
	}
	for _, address := range addresses {
		if address.IfName != InternalBridge {
			continue
		}
		for _, info := range address.AddrInfo {
			if info.Local != "" {
				state.HostAddresses = append(state.HostAddresses, info.Family+" "+info.Local)
				addr, err := netip.ParseAddr(info.Local)
				if err != nil || info.Family != "inet6" || info.Scope != "link" || !addr.Is6() || !addr.IsLinkLocalUnicast() {
					linkLocalOnly = false
				}
			}
		}
	}
	for _, route := range routes {
		if route.Dev == InternalBridge && (route.Dst == "default" || route.Gateway != "") {
			state.Gateway = route.Dst + " via " + route.Gateway
		}
	}
	state.VLANAware = strings.Contains(detail, "vlan_filtering 1") || strings.Contains(detail, "vlan_filtering on")
	state.Configured = compatibleBridgeConfig(config)
	// A managed physical trunk is valid only when the persisted bridge stanza
	// names the same single member. A physical member on a virtual-only stanza
	// remains a conflict and is never adopted implicitly.
	configuredTrunk := configuredBridgePort(config)
	physicalTrunk := configuredTrunk != "" && containsString(state.PhysicalEthernetMembers, configuredTrunk)
	virtualBridge := configuredTrunk == "none" && len(state.PhysicalEthernetMembers) == 0
	state.Adoptable = state.Exists && state.Up && state.VLANAware && state.Configured && (virtualBridge || physicalTrunk) && state.Gateway == "" && linkLocalOnly

	if !state.Exists {
		state.Detail = "vmbr1 is absent"
	} else if !state.Up {
		state.Detail = "vmbr1 is not up"
	} else if len(state.HostAddresses) > 0 {
		state.Detail = "vmbr1 has an unexpected host address"
	} else if state.Gateway != "" {
		state.Detail = "vmbr1 has an unexpected gateway route"
	} else if !state.VLANAware {
		state.Detail = "vmbr1 is not VLAN-aware"
	} else if !state.Configured {
		state.Detail = "vmbr1 configuration ownership or shape is unknown"
	}
	if state.Adoptable {
		if physicalTrunk {
			state.Detail = "vmbr1 is compatible with the managed physical VLAN trunk and host-IPv6 suppression"
		} else {
			state.Detail = "vmbr1 is compatible with explicit adoption and host-IPv6 suppression"
		}
	}
	_ = membership
	return state
}

// Reject unrecognized persistent directives, including addresses, gateways and
// hooks. ifquery resolves included files; a fixed line window cannot.
func compatibleBridgeConfig(config string) bool {
	seen := map[string]bool{}
	for _, line := range strings.Split(config, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		line = strings.Join(strings.Fields(line), " ")
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "bridge-ports" && fields[1] != "none" {
			if !safeIdentifier(fields[1]) || seen["bridge-ports"] {
				return false
			}
			seen["bridge-ports"] = true
			continue
		}
		switch line {
		case "auto vmbr1", "iface vmbr1 inet manual", "iface vmbr1 inet6 manual", "bridge-ports none", "bridge-stp off", "bridge-fd 0", "bridge-vlan-aware yes", "bridge-vids 2-4094", "bridge-vids 5 10 20 30 40 99":
		default:
			return false
		}
		if seen[line] && line != "auto vmbr1" {
			return false
		}
		seen[line] = true
	}
	port := configuredBridgePort(config)
	vids := seen["bridge-vids 2-4094"] || seen["bridge-vids 5 10 20 30 40 99"]
	if port != "" && port != "none" {
		vids = seen["bridge-vids 5 10 20 30 40 99"]
	}
	return seen["auto vmbr1"] && seen["iface vmbr1 inet manual"] && port != "" && seen["bridge-vlan-aware yes"] && vids
}

func configuredBridgePort(config string) string {
	for _, line := range strings.Split(config, "\n") {
		fields := strings.Fields(strings.TrimSpace(strings.SplitN(line, "#", 2)[0]))
		if len(fields) == 2 && fields[0] == "bridge-ports" {
			return fields[1]
		}
	}
	return ""
}

func routeUsesManagement(route string) bool {
	return strings.Contains(route, "via 10.10.99.1 dev vmbr1.99")
}

func trunkMatches(config NetworkConfig, links []ipLink, configured string) bool {
	if config.PhysicalTrunk == "" {
		return configured == "none"
	}
	if configured != config.PhysicalTrunk {
		return false
	}
	for _, link := range links {
		if link.IfName == config.PhysicalTrunk {
			return link.Master == InternalBridge && link.LinkType == "ether" && strings.EqualFold(link.Address, config.PhysicalTrunkMAC)
		}
	}
	return false
}

// ifupdown2 must actually execute the persistent interface-up hook.
const bridgeHookSupportCheck = `grep -Eq '^addon_scripts_support[[:space:]]*=[[:space:]]*1[[:space:]]*(#.*)?$' /etc/network/ifupdown2/ifupdown2.conf`

const bridgeSysctlPath = "/etc/sysctl.d/70-boetticher-vmbr1.conf"
const bridgeHookPath = "/etc/network/if-up.d/boetticher-vmbr1"
const managementConfigPath = "/etc/network/interfaces.d/boetticher-management"
const bridgeSysctl = "# Keep the Proxmox host off the virtual LAB at L3.\nnet.ipv6.conf.vmbr1.disable_ipv6=1\n"
const bridgeHook = "#!/bin/sh\n# Managed by Boetticher: vmbr1 host IPv6 suppression.\nset -eu\n[ \"${IFACE:-}\" = vmbr1 ] || exit 0\nsysctl -q -w net.ipv6.conf.vmbr1.disable_ipv6=1\n"
const managementConfig = "# Managed by Boetticher: Proxmox MGMT\nauto vmbr1.99\niface vmbr1.99 inet static\n    address 10.10.99.5/24\n    vlan-raw-device vmbr1\n    up sysctl -q -w net/ipv6/conf/vmbr1.99/disable_ipv6=1\n    up ip route replace 10.10.0.0/16 via 10.10.99.1 dev vmbr1.99\n"

func shellLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

func networkOwnershipCommand() string {
	return "set -eu; if " + bridgeHookSupportCheck + " && " + ownedFileCheck(bridgeSysctlPath, bridgeSysctl) + " && " + ownedFileCheck(bridgeHookPath, bridgeHook) + " && test -x " + bridgeHookPath + "; then echo owned; fi"
}

func managementOwnershipCommand() string {
	return "set -eu; if " + ownedFileCheck(managementConfigPath, managementConfig) + "; then echo owned; fi"
}

func ownedFileCheck(path, content string) string {
	return "test ! -L " + path + " && test -f " + path + " && printf %s " + shellLiteral(content) + " | cmp -s - " + path
}

func NetworkConfigurationCommand(plan NetworkPlan, adopt ...bool) (string, error) {
	if plan.State != "absent" && !(plan.State == "adoptable" && len(adopt) == 1 && adopt[0]) {
		return "", fmt.Errorf("network state %s requires an absent bridge or explicit compatible adoption: %s", plan.State, plan.Detail)
	}
	command := `set -eu
file=/etc/network/interfaces
backup=/root/boetticher-network-pre-change.interfaces
for dir in /etc/network /etc/sysctl.d /etc/network/if-up.d; do test -d "$dir"; test ! -L "$dir"; done
test -f "$file"; test ! -L "$file"
`
	command += bridgeHookSupportCheck + "\n"
	for _, file := range []struct{ path, content string }{{bridgeSysctlPath, bridgeSysctl}, {bridgeHookPath, bridgeHook}} {
		command += "test ! -L " + file.path + "; if [ -e " + file.path + " ]; then " + ownedFileCheck(file.path, file.content) + "; fi\n"
	}
	if plan.Config.PhysicalTrunk != "" {
		command += "test ! -L /etc/network/interfaces.d; if [ -e " + managementConfigPath + " ]; then " + ownedFileCheck(managementConfigPath, managementConfig) + "; fi\n"
		command += "if grep -Fqx 'source /etc/network/interfaces.d/*' \"$file\" && grep -Fqx 'source-directory /etc/network/interfaces.d' \"$file\"; then tmp=$(mktemp /etc/network/interfaces.boetticher.XXXXXX); trap 'rm -f \"$tmp\"' EXIT; sed '/^source-directory \\/etc\\/network\\/interfaces\\.d$/d' \"$file\" >\"$tmp\"; chmod 644 \"$tmp\"; mv -f \"$tmp\" \"$file\"; fi\n"
	}
	if plan.State == "absent" {
		port := plan.Config.PhysicalTrunk
		vids := "2-4094"
		if port != "" {
			vids = "5 10 20 30 40 99"
		}
		bridgePort := "none"
		if port != "" {
			bridgePort = port
		}
		command += `test ! -e "$backup"; test ! -L "$backup"
install -m 600 "$file" "$backup"
tmp=$(mktemp /etc/network/interfaces.boetticher.XXXXXX)
trap 'rm -f "$tmp"' EXIT
cat "$file" >"$tmp"
		`
		command += fmt.Sprintf("printf '%%s\\n' '' '# Managed by Boetticher: internal VLAN trunk' 'auto vmbr1' 'iface vmbr1 inet manual' '    bridge-ports %s' '    bridge-stp off' '    bridge-fd 0' '    bridge-vlan-aware yes' '    bridge-vids %s' 'iface vmbr1 inet6 manual' >>\"$tmp\"\n", bridgePort, vids)
		command += `
chmod 644 "$tmp"; mv -f "$tmp" "$file"
if ! ifup --syntax-check vmbr1; then install -m 644 "$backup" "$file"; exit 82; fi
		`
	}
	if plan.State == "adoptable" && plan.Config.PhysicalTrunk != "" {
		port := plan.Config.PhysicalTrunk
		command += "# Only change the exact legacy Boetticher access-port VLAN list.\n" +
			"if awk 'BEGIN { p=0; n=0; bad=0 } $1 == \"iface\" { p=($2 == \"" + port + "\") } p && $1 == \"bridge-vids\" { if ($2 == \"20\" && $3 == \"40\" && NF == 3) n++; else if (!($2 == \"5\" && $3 == \"10\" && $4 == \"20\" && $5 == \"30\" && $6 == \"40\" && $7 == \"99\" && NF == 7)) bad=1 } END { exit bad || n > 1 }' \"$file\"; then :; else exit 83; fi\n" +
			"if awk 'BEGIN { p=0; n=0 } $1 == \"iface\" { p=($2 == \"" + port + "\") } p && $1 == \"bridge-vids\" && $2 == \"20\" && $3 == \"40\" && NF == 3 { n++ } END { exit n == 1 ? 0 : 1 }' \"$file\"; then tmp=$(mktemp /etc/network/interfaces.boetticher.XXXXXX); trap 'rm -f \"$tmp\"' EXIT; awk 'BEGIN { p=0 } $1 == \"iface\" { p=($2 == \"" + port + "\") } p && $1 == \"bridge-vids\" && $2 == \"20\" && $3 == \"40\" && NF == 3 { print \"    bridge-vids 5 10 20 30 40 99\"; next } { print }' \"$file\" >\"$tmp\"; chmod 644 \"$tmp\"; mv -f \"$tmp\" \"$file\"; ifreload -a; fi\n"
	}
	if plan.Config.PhysicalTrunk != "" {
		command += "mgmt=" + managementConfigPath + "\ntest ! -L \"$mgmt\"\ntmp=$(mktemp \"$mgmt.XXXXXX\")\ntrap 'rm -f \"$tmp\"' EXIT\nprintf %s " + shellLiteral(managementConfig) + " >\"$tmp\"\nchmod 644 \"$tmp\"; mkdir -p /etc/network/interfaces.d; mv -f \"$tmp\" \"$mgmt\"\nifup --syntax-check vmbr1.99\n"
	}
	for _, file := range []struct{ path, content, mode string }{{bridgeSysctlPath, bridgeSysctl, "644"}, {bridgeHookPath, bridgeHook, "755"}} {
		command += "tmp=$(mktemp " + file.path + ".XXXXXX)\ntrap 'rm -f \"$tmp\"' EXIT\nprintf %s " + shellLiteral(file.content) + " >\"$tmp\"\nchmod " + file.mode + " \"$tmp\"; mv -f \"$tmp\" " + file.path + "\n"
	}
	if plan.State == "absent" {
		command += "ifup vmbr1\n"
	}
	if plan.Config.PhysicalTrunk != "" {
		command += "ifup vmbr1.99\ntest \"$(cat /proc/sys/net/ipv6/conf/vmbr1.99/disable_ipv6)\" = 1\n"
	}
	command += `sysctl -q -w net.ipv6.conf.vmbr1.disable_ipv6=1
test "$(cat /proc/sys/net/ipv6/conf/vmbr1/disable_ipv6)" = 1
`
	return command, nil
}
