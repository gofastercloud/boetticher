package cli

import (
	"context"
	"fmt"
	"io"

	networkmodel "github.com/gofastercloud/boetticher/internal/network"
	"github.com/gofastercloud/boetticher/internal/proxmox"
)

func rollbackTrunkChange(ctx context.Context, client *proxmox.Client, node, interfaceName, bootstrapAddress, message string, cause error) error {
	if rollbackErr := proxmox.DetachTrunk(ctx, client, node, interfaceName, bootstrapAddress); rollbackErr != nil {
		return fmt.Errorf("%s and rollback failed: %v; cause: %w", message, rollbackErr, cause)
	}
	return fmt.Errorf("%s; rollback completed: %w", message, cause)
}

func rollbackDetachedTrunkChange(ctx context.Context, client *proxmox.Client, node, interfaceName, bootstrapAddress, message string, cause error) error {
	if rollbackErr := proxmox.AttachTrunk(ctx, client, node, interfaceName, bootstrapAddress); rollbackErr != nil {
		return fmt.Errorf("%s and rollback failed: %v; cause: %w", message, rollbackErr, cause)
	}
	return fmt.Errorf("%s; rollback completed: %w", message, cause)
}

func printPhysicalDiscovery(out io.Writer, discovery networkmodel.Discovery) {
	fmt.Fprintf(out, "Detected network topology\nUpstream/bootstrap\n  %s\n  address: %s\n  model: %s\n  permanent MAC: %s\n  PCI: %s\n  driver: %s\n  speed: %s\n  carrier: %t\n", discovery.Upstream.Name, valueOrUnknown(discovery.BootstrapAddress), valueOrUnknown(discovery.Upstream.Model), valueOrUnknown(discovery.Upstream.PermanentMAC), valueOrUnknown(discovery.Upstream.PCIAddress), valueOrUnknown(discovery.Upstream.Driver), speedText(discovery.Upstream.SpeedMbps), discovery.Upstream.Carrier)
	if discovery.Mode == networkmodel.ModeSelectionNeeded {
		fmt.Fprintln(out, "Eligible internal trunk interfaces")
		for index, candidate := range discovery.Candidates {
			fmt.Fprintf(out, "  [%d] %s - %s - MAC %s - %s - carrier %t\n", index+1, candidate.Name, valueOrUnknown(candidate.Model), valueOrUnknown(candidate.PermanentMAC), speedText(candidate.SpeedMbps), candidate.Carrier)
		}
		fmt.Fprintln(out, "Select the internal trunk interface with --trunk-interface or the command-specific interface argument.")
	} else if discovery.Trunk != nil {
		fmt.Fprintf(out, "Internal trunk candidate\n  %s\n  model: %s\n  permanent MAC: %s\n  PCI: %s\n  driver: %s\n  speed: %s\n  carrier: %t\n", discovery.Trunk.Name, valueOrUnknown(discovery.Trunk.Model), valueOrUnknown(discovery.Trunk.PermanentMAC), valueOrUnknown(discovery.Trunk.PCIAddress), valueOrUnknown(discovery.Trunk.Driver), speedText(discovery.Trunk.SpeedMbps), discovery.Trunk.Carrier)
	}
	fmt.Fprintf(out, "Proposed platform mapping\n  vmbr0 -> %s\n  vmbr1 -> %s\n  mode: %s\n", discovery.Upstream.Name, trunkName(discovery), discovery.Mode)
}

func trunkName(discovery networkmodel.Discovery) string {
	if discovery.Trunk == nil {
		return "none"
	}
	return discovery.Trunk.Name
}

func valueOrUnknown(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}

func speedText(speedMbps int) string {
	if speedMbps <= 0 {
		return "unknown"
	}
	if speedMbps >= 1000 && speedMbps%1000 == 0 {
		return fmt.Sprintf("%d Gb/s", speedMbps/1000)
	}
	return fmt.Sprintf("%d Mb/s", speedMbps)
}
