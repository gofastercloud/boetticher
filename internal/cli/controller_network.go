package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

func parseNetworkConfigureFlags(args []string) (yes, adopt bool, err error) {
	for _, arg := range args {
		switch {
		case arg == "--yes" && !yes:
			yes = true
		case arg == "--adopt-existing-network" && !adopt:
			adopt = true
		default:
			return false, false, errors.New("usage: boetticher host apply [--adopt-existing-network] [--yes]")
		}
	}
	return yes, adopt, nil
}

func persistNetworkConfig(config controllerhost.LabConfig, network controllerhost.NetworkConfig) error {
	if config.Network != nil && *config.Network == network {
		return nil
	}
	config.Network = &network
	return controllerhost.SaveConfig(config)
}

func sameManagementPath(left, right controllerhost.ManagementPath) bool {
	if left.Address != right.Address || left.Bridge != right.Bridge || left.EgressDevice != right.EgressDevice || left.Gateway != right.Gateway || len(left.Members) != len(right.Members) {
		return false
	}
	for index := range left.Members {
		if left.Members[index] != right.Members[index] {
			return false
		}
	}
	return true
}

func renderNetworkPlan(out io.Writer, plan controllerhost.NetworkPlan) {
	fmt.Fprintln(out, "Host network configuration")
	fmt.Fprintf(out, "\nProtected HOME management\n  Address:        %s\n  Bridge:         %s\n  Physical path:  %s\n  Default route:  %s via %s\n", plan.Management.Address, plan.Management.Bridge, strings.Join(plan.Management.Members, ", "), plan.Management.EgressDevice, plan.Management.Gateway)
	ports := "none"
	if plan.Config.PhysicalTrunk != "" {
		ports = plan.Config.PhysicalTrunk
	}
	fmt.Fprintf(out, "\nDesired bridge state:\n  Bridge:         vmbr1\n  VLAN aware:     yes\n  Host address:   none\n  Host IPv6:      disabled\n  Physical ports: %s\n", ports)
	fmt.Fprintln(out, "\nLogical VLANs:\n  5   TRANSIT\n  10  INFRA\n  20  SERVERS\n  30  TRUSTED\n  40  SANDBOX\n  99  MGMT")
	fmt.Fprintln(out, "\nWill NOT change:\n  vmbr0\n  HOME address\n  HOME default route\n  guests\n  storage\n  firewall rules")
	if plan.State == "adoptable" {
		fmt.Fprintf(out, "\nExisting internal bridge found: vmbr1\n  VLAN aware:       yes\n  Physical members: none\n  Configured IP:    none\n  Runtime address:  %s\n  Gateway:          none\n", strings.Join(plan.Bridge.HostAddresses, ", "))
		fmt.Fprintln(out, "Boetticher can adopt this bridge and disable Host IPv6 on vmbr1.\nRequires --adopt-existing-network and approval.\nWill change:\n  Persist Boetticher ownership of vmbr1\n  Disable the Proxmox Host IPv6 stack on vmbr1")
	}
	if plan.State == "conflict" {
		fmt.Fprintf(out, "\nNetwork state: conflict — %s\n", plan.Detail)
	}
}

func renderNetworkStatus(out io.Writer, plan controllerhost.NetworkPlan) error {
	fmt.Fprintln(out, "Internal network")
	managementOK := plan.Management.Address == "192.168.4.5" && plan.Management.Bridge != "" && plan.Management.EgressDevice == plan.Management.Bridge && plan.Management.Gateway != ""
	if managementOK {
		fmt.Fprintf(out, "PASS  HOME management   %s / 192.168.4.5\n", plan.Management.Bridge)
		fmt.Fprintf(out, "PASS  Default route     %s via %s\n", plan.Management.EgressDevice, plan.Management.Gateway)
	} else {
		fmt.Fprintln(out, "FAIL  HOME management   path is absent or ambiguous")
		fmt.Fprintln(out, "FAIL  Default route     path is absent or ambiguous")
	}
	bridgeOK := plan.State == "exact"
	if bridgeOK {
		fmt.Fprintln(out, "PASS  Internal bridge   vmbr1")
		fmt.Fprintln(out, "PASS  VLAN awareness    enabled")
		fmt.Fprintln(out, "PASS  Host IP           none")
		fmt.Fprintln(out, "PASS  Host IPv6         disabled (persistent and live)")
		fmt.Fprintln(out, "PASS  Physical member   none")
		fmt.Fprintln(out, "Logical VLANs:\n  5,10,20,30,40,99")
		fmt.Fprintln(out, "\nInternal network: PASS")
		return nil
	}
	fmt.Fprintf(out, "FAIL  Internal bridge   %s\n", plan.Detail)
	fmt.Fprintln(out, "\nInternal network: FAIL")
	return errors.New("internal Host network is not ready")
}
