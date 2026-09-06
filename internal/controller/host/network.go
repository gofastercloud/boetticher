package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const InternalBridge = "vmbr1"

type VLANConfig struct {
	Transit int `yaml:"transit"`
	Infra   int `yaml:"infra"`
	Servers int `yaml:"servers"`
	Trusted int `yaml:"trusted"`
	Sandbox int `yaml:"sandbox"`
	Mgmt    int `yaml:"mgmt"`
}

type NetworkConfig struct {
	InternalBridge string     `yaml:"internal_bridge"`
	VLANs          VLANConfig `yaml:"vlans"`
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
	VLANAware       bool
	HostAddresses   []string
	Gateway         string
	PhysicalMembers []string
	Configured      bool
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
	return NetworkConfig{InternalBridge: InternalBridge, VLANs: VLANConfig{Transit: 5, Infra: 10, Servers: 20, Trusted: 30, Sandbox: 40, Mgmt: 99}}
}

func ValidateNetworkConfig(config NetworkConfig) error {
	if config.InternalBridge != InternalBridge {
		return fmt.Errorf("internal bridge must be %s", InternalBridge)
	}
	values := []int{config.VLANs.Transit, config.VLANs.Infra, config.VLANs.Servers, config.VLANs.Trusted, config.VLANs.Sandbox, config.VLANs.Mgmt}
	seen := map[int]bool{}
	for _, value := range values {
		if value < 1 || value > 4094 || seen[value] {
			return errors.New("network VLAN IDs must be unique values from 1 through 4094")
		}
		seen[value] = true
	}
	return nil
}

type ipLink struct {
	IfName   string `json:"ifname"`
	LinkType string `json:"link_type"`
	Master   string `json:"master"`
}

type ipAddress struct {
	IfName   string `json:"ifname"`
	AddrInfo []struct {
		Family string `json:"family"`
		Local  string `json:"local"`
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
	configResult, err := transport.Run(ctx, "grep -n -A10 -B2 '^auto vmbr1$' /etc/network/interfaces 2>/dev/null || true")
	if err != nil {
		return NetworkPlan{}, fmt.Errorf("read vmbr1 configuration: %w", err)
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
	bridge := bridgeState(links, addresses, routes, string(bridgeResult.Stdout), string(detailResult.Stdout), string(configResult.Stdout))
	plan := NetworkPlan{Management: management, Bridge: bridge, Config: want, Links: linksResult.Stdout, Addresses: addressesResult.Stdout, Routes: routesResult.Stdout}
	if management.Address != "192.168.4.5" || management.Bridge == "" || management.EgressDevice == "" || management.Gateway == "" || management.Bridge != management.EgressDevice || len(management.Members) == 0 {
		plan.State = "conflict"
		plan.Detail = "HOME management path is absent or ambiguous"
		return plan, nil
	}
	if !bridge.Exists {
		plan.State = "absent"
		plan.Detail = "vmbr1 is absent and can be created additively"
	} else if bridge.VLANAware && len(bridge.HostAddresses) == 0 && bridge.Gateway == "" && len(bridge.PhysicalMembers) == 0 && bridge.Configured {
		plan.State = "exact"
		plan.Detail = "vmbr1 already has the expected virtual-only VLAN-aware shape"
	} else {
		plan.State = "conflict"
		plan.Detail = bridge.Detail
	}
	return plan, nil
}

func managementPath(links []ipLink, addresses []ipAddress, routes []ipRoute, routeOutput string) ManagementPath {
	path := ManagementPath{Address: "192.168.4.5"}
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
	for _, link := range links {
		if link.IfName == InternalBridge {
			state.Exists = true
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
			}
		}
	}
	for _, route := range routes {
		if route.Dev == InternalBridge && route.Dst == "default" {
			state.Gateway = route.Gateway
		}
	}
	state.VLANAware = strings.Contains(detail, "vlan_filtering 1") || strings.Contains(detail, "vlan_filtering on")
	state.Configured = strings.Contains(config, "bridge-ports none") && strings.Contains(config, "bridge-vlan-aware yes") && strings.Contains(config, "bridge-vids 2-4094")
	if !state.Exists {
		state.Detail = "vmbr1 is absent"
	} else if len(state.PhysicalMembers) > 0 {
		state.Detail = "vmbr1 has an unexpected physical member"
	} else if len(state.HostAddresses) > 0 {
		state.Detail = "vmbr1 has an unexpected host address"
	} else if state.Gateway != "" {
		state.Detail = "vmbr1 has an unexpected gateway route"
	} else if !state.VLANAware {
		state.Detail = "vmbr1 is not VLAN-aware"
	} else if !state.Configured {
		state.Detail = "vmbr1 configuration ownership or shape is unknown"
	}
	_ = membership
	return state
}

func NetworkConfigurationCommand(plan NetworkPlan) (string, error) {
	if plan.State != "absent" {
		return "", fmt.Errorf("network state %s is not eligible for additive configuration: %s", plan.State, plan.Detail)
	}
	return `set -eu; file=/etc/network/interfaces; backup=/root/boetticher-network-pre-change.interfaces; if [ -e "$backup" ]; then echo 'existing network recovery copy found; refusing to overwrite it' >&2; exit 81; fi; install -m 600 "$file" "$backup"; tmp="$(mktemp /etc/network/interfaces.boetticher.XXXXXX)"; trap 'rm -f "$tmp" "$tmp".append' EXIT; cat "$file" >"$tmp"; printf '%s\n' '' '# Managed by Boetticher Phase 3B: virtual-only internal bridge' 'auto vmbr1' 'iface vmbr1 inet manual' '    bridge-ports none' '    bridge-stp off' '    bridge-fd 0' '    bridge-vlan-aware yes' '    bridge-vids 2-4094' 'iface vmbr1 inet6 manual' >"$tmp".append; cat "$tmp".append >>"$tmp"; install -m 644 "$tmp" "$file"; if ! ifup --no-act vmbr1; then install -m 644 "$backup" "$file"; exit 82; fi; ifup vmbr1; ip -d link show vmbr1 | grep -Eq 'vlan_filtering (1|on)'; test -z "$(ip -json address show dev vmbr1 | grep -F '"local"' || true)"; test -z "$(bridge link | awk '$NF == "vmbr1" { print; exit }')"`, nil
}
