package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
	networkmodel "github.com/gofastercloud/boetticher/internal/network"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/site"
)

func runNetwork(args []string, out io.Writer) error {
	if len(args) < 2 || args[0] != "trunk" {
		return fmt.Errorf("usage: boetticher network trunk status|attach|detach [--site DIR]")
	}
	command := args[1]
	rest := args[2:]
	interfaceName := ""
	if (command == "attach" || command == "detach") && len(rest) > 0 && !strings.HasPrefix(rest[0], "--") {
		interfaceName = rest[0]
		rest = rest[1:]
	}
	fs := flag.NewFlagSet("network trunk", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	confirm := fs.Bool("confirm", false, "confirm a live network change")
	live := fs.Bool("live", false, "inspect the Proxmox node instead of only the site model")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	proxmoxCA := fs.String("proxmox-ca", "", "Proxmox API CA PEM file")
	insecure := fs.Bool("insecure", false, "explicitly allow self-signed Proxmox API TLS")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	switch command {
	case "status":
		if s.PhysicalNetwork.Mode == model.ModeVirtualOnly {
			fmt.Fprintln(out, "Physical trunk: virtual-only")
		} else {
			fmt.Fprintf(out, "Physical trunk: %s attached\n", s.PhysicalNetwork.Trunk.Name)
		}
		if !*live {
			return nil
		}
		client, _, err := loadProxmoxClient(*siteDir, s, *ageIdentity, *proxmoxCA, *insecure)
		if err != nil {
			return err
		}
		node, err := client.SingleNode(context.Background())
		if err != nil {
			return err
		}
		var interfaces []proxmox.NetworkInterface
		if err := client.NodeNetwork(context.Background(), node, &interfaces); err != nil {
			return err
		}
		discovery, err := proxmox.DiscoverPhysicalNetwork(context.Background(), client, node, s.BootstrapAddress, s.PhysicalNetwork.Trunk.Name)
		if err != nil {
			return err
		}
		printPhysicalDiscovery(out, discovery)
		for _, iface := range interfaces {
			if iface.Iface == "vmbr1" {
				fmt.Fprintf(out, "vmbr1: PASS bridge ports=%s vlan-aware=%t\n", iface.BridgePorts, iface.BridgeVLANAware)
				return nil
			}
		}
		return errors.New("vmbr1 is absent on Proxmox")
	case "attach", "detach":
		if interfaceName == "" {
			return fmt.Errorf("network trunk %s requires an interface name", command)
		}
		if s.BootstrapAddress == "" {
			return fmt.Errorf("cannot prove the interface is not the HOME/bootstrap path until bootstrap-endpoint is set")
		}
		client, _, err := loadProxmoxClient(*siteDir, s, *ageIdentity, *proxmoxCA, *insecure)
		if err != nil {
			return err
		}
		ctx := context.Background()
		node, err := client.SingleNode(ctx)
		if err != nil {
			return err
		}
		var observedDiscovery *networkmodel.Discovery
		if command == "attach" {
			discovery, discoveryErr := proxmox.DiscoverPhysicalNetworkWithSelection(ctx, client, node, s.BootstrapAddress, s.PhysicalNetwork.Trunk.Name, interfaceName)
			if discoveryErr != nil {
				return discoveryErr
			}
			observedDiscovery = &discovery
			printPhysicalDiscovery(out, discovery)
			if !*confirm {
				return fmt.Errorf("network trunk attach is a potentially locking live change; review the proposal and repeat with --confirm")
			}
			if err := proxmox.AttachTrunk(ctx, client, node, interfaceName, s.BootstrapAddress); err != nil {
				return err
			}
			s.PhysicalNetwork.Mode = model.ModePhysicalTrunk
			s.PhysicalNetwork.Trunk.Name = interfaceName
			if discovery.Trunk != nil {
				s.PhysicalNetwork.Trunk.PermanentMAC = discovery.Trunk.PermanentMAC
				s.PhysicalNetwork.Trunk.PCIAddress = discovery.Trunk.PCIAddress
			}
			if discovery.Upstream.Name != "" {
				s.PhysicalNetwork.Upstream = model.PhysicalNIC{Name: discovery.Upstream.Name, PermanentMAC: discovery.Upstream.PermanentMAC, PCIAddress: discovery.Upstream.PCIAddress}
			}
			var after []proxmox.NetworkInterface
			if err := client.NodeNetwork(ctx, node, &after); err != nil {
				return rollbackTrunkChange(ctx, client, node, interfaceName, s.BootstrapAddress, "HOLD: trunk attach could not be re-read", err)
			}
			if _, err := proxmox.ValidatePhysicalBinding(s, after); err != nil {
				return rollbackTrunkChange(ctx, client, node, interfaceName, s.BootstrapAddress, "HOLD: trunk attach failed post-change validation", err)
			}
			postDiscovery, err := proxmox.AnalyzePhysicalNetwork(after, s.BootstrapAddress, interfaceName)
			if err != nil {
				return rollbackTrunkChange(ctx, client, node, interfaceName, s.BootstrapAddress, "HOLD: trunk attach produced ambiguous physical evidence", err)
			}
			observedDiscovery = &postDiscovery
		} else {
			if s.PhysicalNetwork.Trunk.Name != interfaceName {
				return fmt.Errorf("site records physical trunk %q, not %q", s.PhysicalNetwork.Trunk.Name, interfaceName)
			}
			if !*confirm {
				return fmt.Errorf("network trunk detach is a potentially locking live change; repeat with --confirm")
			}
			if err := proxmox.DetachTrunk(ctx, client, node, interfaceName, s.BootstrapAddress); err != nil {
				return err
			}
			s.PhysicalNetwork.Mode = model.ModeVirtualOnly
			s.PhysicalNetwork.Trunk = model.PhysicalNIC{}
			var after []proxmox.NetworkInterface
			if err := client.NodeNetwork(ctx, node, &after); err != nil {
				return rollbackDetachedTrunkChange(ctx, client, node, interfaceName, s.BootstrapAddress, "HOLD: trunk detach could not be re-read", err)
			}
			if _, err := proxmox.ValidatePhysicalBinding(s, after); err != nil {
				return rollbackDetachedTrunkChange(ctx, client, node, interfaceName, s.BootstrapAddress, "HOLD: trunk detach failed post-change validation", err)
			}
			postDiscovery, err := proxmox.AnalyzePhysicalNetwork(after, s.BootstrapAddress, "")
			if err != nil {
				return rollbackDetachedTrunkChange(ctx, client, node, interfaceName, s.BootstrapAddress, "HOLD: trunk detach produced ambiguous physical evidence", err)
			}
			observedDiscovery = &postDiscovery
		}
		if err := site.Save(*siteDir, s); err != nil {
			return fmt.Errorf("HOLD: trunk changed but physical binding could not be persisted: %w", err)
		}
		if err := writeModelProjections(*siteDir, s); err != nil {
			return fmt.Errorf("HOLD: trunk changed but projections could not be regenerated: %w", err)
		}
		if observedDiscovery != nil {
			if err := writePhysicalDiscovery(*siteDir, s, *observedDiscovery); err != nil {
				return fmt.Errorf("HOLD: trunk changed but physical evidence could not be written: %w", err)
			}
		}
		if err := rebuildPortal(*siteDir, s); err != nil {
			return fmt.Errorf("HOLD: trunk changed but portal could not be regenerated: %w", err)
		}
		fmt.Fprintf(out, "Physical trunk: PASS %s %s vmbr1\n", command, interfaceName)
		return nil
	default:
		return fmt.Errorf("unknown trunk command %q", command)
	}
}

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
