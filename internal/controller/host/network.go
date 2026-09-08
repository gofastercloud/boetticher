package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	InternalBridge  string           `yaml:"internal_bridge"`
	VLANs           VLANConfig       `yaml:"vlans"`
	Domain          string           `yaml:"domain,omitempty"`
	ProtectedRanges *ProtectedRanges `yaml:"protected_ranges,omitempty"`
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
	Exists          bool
	Up              bool
	VLANAware       bool
	HostAddresses   []string
	Gateway         string
	PhysicalMembers []string
	Configured      bool
	Adoptable       bool
	IPv6Disabled    bool
	Owned           bool
	Detail          string
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

type ipLink struct {
	IfName    string   `json:"ifname"`
	LinkType  string   `json:"link_type"`
	Master    string   `json:"master"`
	OperState string   `json:"operstate"`
	Flags     []string `json:"flags"`
}

type ipAddress struct {
	IfName   string `json:"ifname"`
	AddrInfo []struct {
		Family string `json:"family"`
		Local  string `json:"local"`
		Scope  string `json:"scope"`
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
	} else if bridge.Up && bridge.VLANAware && len(bridge.HostAddresses) == 0 && bridge.Gateway == "" && bridge.Configured && bridge.Owned && bridge.IPv6Disabled {
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
	state.Adoptable = state.Exists && state.Up && state.VLANAware && state.Configured && len(state.PhysicalMembers) == 0 && state.Gateway == "" && linkLocalOnly

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
		state.Detail = "vmbr1 is compatible with explicit adoption and host-IPv6 suppression"
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
		switch line {
		case "auto vmbr1", "iface vmbr1 inet manual", "iface vmbr1 inet6 manual", "bridge-ports none", "bridge-stp off", "bridge-fd 0", "bridge-vlan-aware yes", "bridge-vids 2-4094":
		default:
			return false
		}
		if seen[line] && line != "auto vmbr1" {
			return false
		}
		seen[line] = true
	}
	return seen["auto vmbr1"] && seen["iface vmbr1 inet manual"] && seen["bridge-ports none"] && seen["bridge-vlan-aware yes"] && seen["bridge-vids 2-4094"]
}

// ifupdown2 must actually execute the persistent interface-up hook.
const bridgeHookSupportCheck = `grep -Eq '^addon_scripts_support[[:space:]]*=[[:space:]]*1[[:space:]]*(#.*)?$' /etc/network/ifupdown2/ifupdown2.conf`

const bridgeSysctlPath = "/etc/sysctl.d/70-boetticher-vmbr1.conf"
const bridgeHookPath = "/etc/network/if-up.d/boetticher-vmbr1"
const bridgeSysctl = "# Keep the Proxmox host off the virtual LAB at L3.\nnet.ipv6.conf.vmbr1.disable_ipv6=1\n"
const bridgeHook = "#!/bin/sh\n# Managed by Boetticher: vmbr1 host IPv6 suppression.\nset -eu\n[ \"${IFACE:-}\" = vmbr1 ] || exit 0\nsysctl -q -w net.ipv6.conf.vmbr1.disable_ipv6=1\n"

func shellLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

func networkOwnershipCommand() string {
	return "set -eu; if " + bridgeHookSupportCheck + " && " + ownedFileCheck(bridgeSysctlPath, bridgeSysctl) + " && " + ownedFileCheck(bridgeHookPath, bridgeHook) + " && test -x " + bridgeHookPath + "; then echo owned; fi"
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
	if plan.State == "absent" {
		command += `test ! -e "$backup"; test ! -L "$backup"
install -m 600 "$file" "$backup"
tmp=$(mktemp /etc/network/interfaces.boetticher.XXXXXX)
trap 'rm -f "$tmp"' EXIT
cat "$file" >"$tmp"
printf '%s\n' '' '# Managed by Boetticher Phase 3B: virtual-only internal bridge' 'auto vmbr1' 'iface vmbr1 inet manual' '    bridge-ports none' '    bridge-stp off' '    bridge-fd 0' '    bridge-vlan-aware yes' '    bridge-vids 2-4094' 'iface vmbr1 inet6 manual' >>"$tmp"
chmod 644 "$tmp"; mv -f "$tmp" "$file"
if ! ifup --no-act vmbr1; then install -m 644 "$backup" "$file"; exit 82; fi
`
	}
	for _, file := range []struct{ path, content, mode string }{{bridgeSysctlPath, bridgeSysctl, "644"}, {bridgeHookPath, bridgeHook, "755"}} {
		command += "tmp=$(mktemp " + file.path + ".XXXXXX)\ntrap 'rm -f \"$tmp\"' EXIT\nprintf %s " + shellLiteral(file.content) + " >\"$tmp\"\nchmod " + file.mode + " \"$tmp\"; mv -f \"$tmp\" " + file.path + "\n"
	}
	if plan.State == "absent" {
		command += "ifup vmbr1\n"
	}
	command += `sysctl -q -w net.ipv6.conf.vmbr1.disable_ipv6=1
test "$(cat /proc/sys/net/ipv6/conf/vmbr1/disable_ipv6)" = 1
`
	return command, nil
}
