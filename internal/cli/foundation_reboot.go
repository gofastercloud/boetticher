package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

func runFoundationReboot(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("foundation reboot", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	yes := fs.Bool("yes", false, "confirm rebooting the enrolled Proxmox host")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || !*yes {
		return errors.New("foundation reboot requires --yes")
	}
	if err := requireControllerReady(); err != nil {
		return err
	}
	config, err := controllerhost.LoadConfig()
	if err != nil {
		return err
	}
	if config.Proxmox.Node == "" {
		return errors.New("host enrollment is required before a foundation reboot")
	}
	transport, err := controllerhost.TransportFor(config)
	if err != nil {
		return err
	}
	inventory, err := controllerhost.Collect(context.Background(), transport, false)
	if err != nil {
		return fmt.Errorf("verify Proxmox before reboot: %w", err)
	}
	if len(inventory.Nodes) != 1 || inventory.Nodes[0].Node != config.Proxmox.Node {
		return fmt.Errorf("Proxmox node identity mismatch: expected %s", config.Proxmox.Node)
	}
	if len(inventory.Guests) != 0 {
		return fmt.Errorf("foundation reboot requires an empty guest inventory; found %s", guestList(inventory.Guests))
	}
	if _, err := transport.Run(context.Background(), "systemctl reboot"); err != nil {
		return fmt.Errorf("Proxmox reboot failed: %w", err)
	}
	fmt.Fprintln(out, "Proxmox reboot requested.")
	return nil
}
