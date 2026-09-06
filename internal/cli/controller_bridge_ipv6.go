package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

func runControllerBridgeIPv6(args []string, out io.Writer) error {
	if len(args) != 0 {
		return errors.New("usage: boetticher network test bridge-ipv6")
	}
	if err := requireControllerReady(); err != nil {
		return err
	}
	config, err := controllerhost.LoadConfig()
	if err != nil {
		return err
	}
	if config.Proxmox.Node == "" {
		return errors.New("host enrollment is required before the IPv6 bridge test")
	}
	transport, err := controllerhost.TransportFor(config)
	if err != nil {
		return err
	}
	transport.Timeout = 10 * time.Minute
	ctx := context.Background()
	inventory, err := controllerhost.Collect(ctx, transport, false)
	if err != nil {
		return fmt.Errorf("inspect Proxmox guests before IPv6 bridge test: %w", err)
	}
	if len(inventory.Guests) != 0 {
		return fmt.Errorf("IPv6 bridge test requires an empty guest inventory; found %s", guestList(inventory.Guests))
	}
	network, err := controllerhost.DiscoverNetwork(ctx, transport, config)
	if err != nil {
		return err
	}
	if network.State != "exact" {
		return fmt.Errorf("IPv6 bridge test requires an exact healthy vmbr1: %s", network.Detail)
	}
	command, err := controllerhost.BridgeIPv6TestCommand()
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "IPv6 bridge test")
	fmt.Fprintln(out, "  Temporary guests      VMIDs 991 and 992")
	fmt.Fprintln(out, "  Test VLAN             40")
	if _, err := transport.Run(ctx, command); err != nil {
		fmt.Fprintf(out, "\nIPv6 bridge test failed.\n\nFailure detail:\n  %v\n\nPreserved:\n  vmbr0 and HOME management\n  Controller↔Proxmox trust\n  Persistent storage\n\nNext:\n  sudo boetticher network status\n", err)
		return fmt.Errorf("IPv6 bridge test failed: %w", err)
	}
	postInventory, err := controllerhost.Collect(ctx, transport, false)
	if err != nil {
		return fmt.Errorf("IPv6 bridge test passed but cleanup verification failed: %w", err)
	}
	if len(postInventory.Guests) != 0 {
		return fmt.Errorf("IPv6 bridge test passed but temporary guest cleanup failed: %s", guestList(postInventory.Guests))
	}
	postNetwork, err := controllerhost.DiscoverNetwork(ctx, transport, config)
	if err != nil || postNetwork.State != "exact" {
		if err == nil {
			err = fmt.Errorf("vmbr1 state after test is %s: %s", postNetwork.State, postNetwork.Detail)
		}
		return fmt.Errorf("IPv6 bridge test passed but network cleanup verification failed: %w", err)
	}
	fmt.Fprintln(out, "  Link-local forwarding PASS")
	fmt.Fprintln(out, "  Temporary guests      removed")
	fmt.Fprintln(out, "IPv6 bridge test: PASS")
	return nil
}
