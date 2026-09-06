package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/controller"
	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

func runHost(args []string, input io.Reader, out, errOut io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher host <identity|trust|enroll|status|prepare>")
	}
	switch args[0] {
	case "identity":
		return runHostIdentity(args[1:], out)
	case "trust":
		return runHostTrust(args[1:], out)
	case "enroll":
		return runHostEnroll(args[1:], out)
	case "status":
		return runHostStatus(args[1:], out)
	case "prepare":
		return runHostPrepare(args[1:], input, out, errOut)
	default:
		return fmt.Errorf("unknown host command %q", args[0])
	}
}

func requireControllerReady() error {
	checks, err := controller.RunStatus(context.Background(), controller.StatusOptions{})
	if err != nil {
		return fmt.Errorf("read controller readiness: %w", err)
	}
	for _, check := range checks {
		if !check.Passed {
			return fmt.Errorf("controller status must pass before host operations: %s", check.Name)
		}
	}
	return nil
}

func runHostIdentity(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher host identity create|public-key")
	}
	if err := requireControllerReady(); err != nil {
		return err
	}
	switch args[0] {
	case "create":
		if len(args) != 1 {
			return errors.New("usage: boetticher host identity create")
		}
		_, created, err := controllerhost.CreateIdentity(context.Background(), nil)
		if err != nil {
			return err
		}
		if created {
			fmt.Fprintln(out, "Controller SSH identity: CREATED")
		} else {
			fmt.Fprintln(out, "Controller SSH identity: PASS existing Ed25519 identity retained")
		}
		return nil
	case "public-key":
		if len(args) != 1 {
			return errors.New("usage: boetticher host identity public-key")
		}
		key, err := controllerhost.PublicKey()
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, key)
		return err
	default:
		return fmt.Errorf("unknown host identity command %q", args[0])
	}
}

func runHostTrust(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "import" {
		return errors.New("usage: boetticher host trust import --address IPv4 --key 'ssh-ed25519 ...'")
	}
	fs := flag.NewFlagSet("host trust import", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	address := fs.String("address", "", "verified Proxmox IPv4 address")
	key := fs.String("key", "", "public host key copied from the trusted Mac")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *address == "" || *key == "" {
		return errors.New("usage: boetticher host trust import --address IPv4 --key 'ssh-ed25519 ...'")
	}
	if err := requireControllerReady(); err != nil {
		return err
	}
	changed, err := controllerhost.ImportTrust(*address, *key)
	if err != nil {
		return err
	}
	if changed {
		fmt.Fprintln(out, "Proxmox host trust: IMPORTED")
	} else {
		fmt.Fprintln(out, "Proxmox host trust: PASS existing key retained")
	}
	return nil
}

func parseHostTarget(value string) (string, error) {
	parts := strings.Split(value, "@")
	if len(parts) != 2 || parts[0] != "root" {
		return "", errors.New("host enroll requires root@IPv4")
	}
	ip := net.ParseIP(parts[1])
	if ip == nil || ip.To4() == nil {
		return "", errors.New("host enroll requires root@IPv4")
	}
	return parts[1], nil
}

func runHostEnroll(args []string, out io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: boetticher host enroll root@IPv4")
	}
	if err := requireControllerReady(); err != nil {
		return err
	}
	address, err := parseHostTarget(args[0])
	if err != nil {
		return err
	}
	transport := controllerhost.Transport{Address: address, User: "root", Identity: controllerhost.PrivateKeyPath, KnownHosts: controllerhost.KnownHostsPath}
	config, inventory, err := controllerhost.Enroll(context.Background(), transport)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Proxmox enrollment: PASS\n  Host       %s\n  Node       %s\n  Version    %s\n  Config     %s\n", inventory.Hostname, config.Proxmox.Node, inventory.Version, controllerhost.LabConfigPath)
	return nil
}

func hostTransport(config controllerhost.LabConfig) (controllerhost.Transport, error) {
	return controllerhost.TransportFor(config)
}

func runHostStatus(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("host status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	details := fs.Bool("details", false, "include guests, storage, disks and networking")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: boetticher host status [--details]")
	}
	if err := requireControllerReady(); err != nil {
		return err
	}
	config, err := controllerhost.LoadConfig()
	if err != nil {
		return err
	}
	transport, err := hostTransport(config)
	if err != nil {
		return err
	}
	inventory, err := controllerhost.Collect(context.Background(), transport, *details)
	if err != nil {
		return err
	}
	baseline, _ := controllerhost.CheckBaseline(context.Background(), transport)
	fmt.Fprintln(out, "Proxmox host")
	fmt.Fprintln(out, "PASS  SSH trust          Verified")
	fmt.Fprintf(out, "PASS  Controller access  %s\n", controllerhost.ConfigSummary(config))
	nodeOK := len(inventory.Nodes) == 1 && inventory.Nodes[0].Node == config.Proxmox.Node
	if nodeOK {
		fmt.Fprintf(out, "PASS  Node identity      %s\n", config.Proxmox.Node)
	} else {
		observed := "none"
		if len(inventory.Nodes) > 0 {
			observed = inventory.Nodes[0].Node
		}
		fmt.Fprintf(out, "FAIL  Node identity      expected %s, observed %s\n", config.Proxmox.Node, observed)
	}
	fmt.Fprintf(out, "PASS  Proxmox            %s\n", strings.TrimSpace(inventory.Version))
	servicesOK := true
	for _, service := range []string{"pve-cluster", "pvedaemon", "pvestatd", "pveproxy"} {
		if inventory.Services[service] != "active" {
			servicesOK = false
		}
	}
	if servicesOK {
		fmt.Fprintln(out, "PASS  Services           Running")
	} else {
		fmt.Fprintln(out, "FAIL  Services           One or more required services are not active")
	}
	if baseline {
		fmt.Fprintln(out, "PASS  Host baseline      Prepared")
	} else {
		fmt.Fprintln(out, "FAIL  Host baseline      Preparation required")
		fmt.Fprintln(out, "\nNext:\n  sudo boetticher host prepare")
	}
	if *details {
		renderHostDetails(out, inventory)
	}
	return nil
}

func renderHostDetails(out io.Writer, inventory controllerhost.Inventory) {
	fmt.Fprintln(out, "\nGuests")
	if len(inventory.Guests) == 0 {
		fmt.Fprintln(out, "  none discovered")
	} else {
		for _, guest := range inventory.Guests {
			fmt.Fprintf(out, "  %d  %-24s %-4s %-10s %s\n", guest.VMID, guest.Name, guest.Type, guest.Status, guest.Node)
		}
	}
	fmt.Fprintln(out, "\nStorage")
	if len(inventory.Storage) == 0 {
		fmt.Fprintln(out, "  none discovered")
	} else {
		for _, storage := range inventory.Storage {
			fmt.Fprintf(out, "  %-16s %-8s active=%d content=%s path=%s\n", storage.ID, storage.Type, storage.Active, storage.Content, storage.Path)
		}
	}
	for _, item := range []struct {
		name string
		data json.RawMessage
	}{{"Physical disks (lsblk)", inventory.Disks}, {"Mounts", inventory.Mounts}, {"Links", inventory.Links}, {"Addresses", inventory.Addresses}, {"Routes", inventory.Routes}, {"LVM PVs", inventory.PVs}, {"LVM VGs", inventory.VGs}, {"LVM LVs", inventory.LVs}} {
		if len(item.data) == 0 {
			continue
		}
		fmt.Fprintf(out, "\n%s\n", item.name)
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, item.data, "  ", "  "); err == nil {
			fmt.Fprintln(out, pretty.String())
		} else {
			fmt.Fprintln(out, string(item.data))
		}
	}
	if strings.TrimSpace(inventory.ByID) != "" {
		fmt.Fprintln(out, "\nStable disk identities (/dev/disk/by-id)")
		fmt.Fprint(out, inventory.ByID)
	}
	if len(inventory.OptionalErrs) > 0 {
		fmt.Fprintln(out, "\nOptional inventory commands unavailable")
		for _, detail := range inventory.OptionalErrs {
			fmt.Fprintf(out, "  %s\n", detail)
		}
	}
}

func runHostPrepare(args []string, input io.Reader, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("host prepare", flag.ContinueOnError)
	fs.SetOutput(errOut)
	yes := fs.Bool("yes", false, "approve the bounded Proxmox host baseline")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: boetticher host prepare [--yes]")
	}
	if err := requireControllerReady(); err != nil {
		return err
	}
	config, err := controllerhost.LoadConfig()
	if err != nil {
		return err
	}
	transport, err := hostTransport(config)
	if err != nil {
		return err
	}
	if _, err := controllerhost.Collect(context.Background(), transport, false); err != nil {
		return fmt.Errorf("revalidate Proxmox host before preparation: %w", err)
	}
	fmt.Fprintln(out, "Proxmox host preparation")
	fmt.Fprintln(out, "\nWill configure:\n  Proxmox package repository policy\n  Required controller prerequisites\n  Headless laptop behavior")
	fmt.Fprintln(out, "\nWill NOT change:\n  Guests\n  Storage\n  Network interfaces\n  Bridges\n  IP addresses\n  Firewall\n  Controller SSH identity\n  Existing recovery access")
	if !*yes {
		if input == nil {
			return errors.New("host preparation requires --yes or an interactive confirmation")
		}
		answer, promptErr := promptYesNo(bufio.NewReader(input), out, "\nContinue? [y/N]: ", false)
		if promptErr != nil {
			return promptErr
		}
		if !answer {
			return errors.New("host preparation cancelled")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	fmt.Fprintln(out, "\nApplying host baseline...")
	if err := controllerhost.RunPrepare(ctx, config, transport, out); err != nil {
		return err
	}
	prepared, err := controllerhost.CheckBaseline(ctx, transport)
	if err != nil {
		return err
	}
	if !prepared {
		return errors.New("host preparation completed but baseline verification failed")
	}
	fmt.Fprintln(out, "Host baseline: PASS")
	return nil
}
