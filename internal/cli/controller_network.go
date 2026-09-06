package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

func shouldRunControllerNetwork(args []string) bool {
	if len(args) == 0 {
		return false
	}
	for _, arg := range args {
		if arg == "--site" || strings.HasPrefix(arg, "--site=") {
			return false
		}
	}
	return args[0] == "plan" || args[0] == "configure" || args[0] == "status"
}

func runControllerNetwork(args []string, input io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher network plan|configure|status")
	}
	if err := requireControllerReady(); err != nil {
		return err
	}
	config, err := controllerhost.LoadConfig()
	if err != nil {
		return err
	}
	transport, err := controllerhost.TransportFor(config)
	if err != nil {
		return err
	}
	ctx := context.Background()
	plan, err := controllerhost.DiscoverNetwork(ctx, transport, config)
	if err != nil {
		return err
	}
	switch args[0] {
	case "plan":
		if len(args) != 1 {
			return errors.New("usage: boetticher network plan")
		}
		renderNetworkPlan(out, plan)
		return nil
	case "status":
		if len(args) != 1 {
			return errors.New("usage: boetticher network status")
		}
		return renderNetworkStatus(out, plan)
	case "configure":
		yes, err := parseYesFlag(args[1:])
		if err != nil {
			return err
		}
		renderNetworkPlan(out, plan)
		if plan.State == "exact" {
			if err := persistNetworkConfig(config, plan.Config); err != nil {
				return err
			}
			fmt.Fprintln(out, "\nInternal network already configured and healthy.\nNo changes required.")
			return nil
		}
		if plan.State != "absent" {
			return fmt.Errorf("network configuration is not eligible: %s", plan.Detail)
		}
		if !yes {
			if input == nil {
				return errors.New("network configuration requires --yes or an interactive confirmation")
			}
			answer, promptErr := promptYesNo(bufio.NewReader(input), out, "\nContinue? [y/N]: ", false)
			if promptErr != nil {
				return promptErr
			}
			if !answer {
				return errors.New("network configuration cancelled")
			}
		}
		fresh, err := controllerhost.DiscoverNetwork(ctx, transport, config)
		if err != nil {
			return err
		}
		if fresh.State != "absent" {
			return fmt.Errorf("network state changed during validation: %s", fresh.Detail)
		}
		command, err := controllerhost.NetworkConfigurationCommand(fresh)
		if err != nil {
			return err
		}
		fmt.Fprintln(out, "\nConfiguring internal network...")
		if _, err := transport.Run(ctx, command); err != nil {
			return fmt.Errorf("network configuration failed: %w", err)
		}
		post, err := controllerhost.DiscoverNetwork(ctx, transport, config)
		if err != nil {
			return fmt.Errorf("network configuration applied, but verification did not complete: %w", err)
		}
		if post.State != "exact" || !sameManagementPath(fresh.Management, post.Management) {
			return errors.New("network configuration applied, but protected management-path verification failed")
		}
		config.Network = &post.Config
		if err := persistNetworkConfig(config, post.Config); err != nil {
			return fmt.Errorf("network configured but desired network choices could not be saved: %w", err)
		}
		fmt.Fprintln(out, "  HOME management path   protected\n  vmbr1                   created\n  VLAN awareness          enabled\n  Fresh SSH verification  passed\nDone.")
		return nil
	default:
		return fmt.Errorf("unknown controller network command %q", args[0])
	}
}

func parseYesFlag(args []string) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	if len(args) == 1 && args[0] == "--yes" {
		return true, nil
	}
	return false, errors.New("usage: boetticher network configure [--yes]")
}

func persistNetworkConfig(config controllerhost.LabConfig, network controllerhost.NetworkConfig) error {
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
	fmt.Fprintln(out, "Internal network foundation")
	fmt.Fprintf(out, "\nProtected HOME management\n  Address:        %s\n  Bridge:         %s\n  Physical path:  %s\n  Default route:  %s via %s\n", plan.Management.Address, plan.Management.Bridge, strings.Join(plan.Management.Members, ", "), plan.Management.EgressDevice, plan.Management.Gateway)
	fmt.Fprintln(out, "\nWill create:\n  Bridge:         vmbr1\n  VLAN aware:     yes\n  Host address:   none\n  Physical ports: none")
	fmt.Fprintln(out, "\nLogical VLANs:\n  5   TRANSIT\n  10  INFRA\n  20  SERVERS\n  30  TRUSTED\n  40  SANDBOX\n  99  MGMT")
	fmt.Fprintln(out, "\nWill NOT change:\n  vmbr0\n  HOME address\n  HOME default route\n  physical NIC membership\n  guests\n  storage\n  firewall rules")
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
		fmt.Fprintln(out, "PASS  Physical member   none")
		fmt.Fprintln(out, "Logical VLANs:\n  5,10,20,30,40,99")
		fmt.Fprintln(out, "\nNetwork foundation: PASS")
		return nil
	}
	fmt.Fprintf(out, "FAIL  Internal bridge   %s\n", plan.Detail)
	fmt.Fprintln(out, "\nNetwork foundation: FAIL")
	return errors.New("network foundation is not ready")
}
