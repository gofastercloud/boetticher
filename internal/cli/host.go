package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/gofastercloud/boetticher/internal/controller"
	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

func runHost(args []string, input io.Reader, out, errOut io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher host <create-identity|show-public-key|import-host-key|enroll|apply|status|plan-storage|teardown|reboot>")
	}
	switch args[0] {
	case "create-identity":
		return runHostCreateIdentity(args[1:], out)
	case "show-public-key":
		return runHostShowPublicKey(args[1:], out)
	case "import-host-key":
		return runHostImportHostKey(args[1:], out)
	case "enroll":
		return runHostEnroll(args[1:], out)
	case "apply":
		return runHostApply(args[1:], input, out, errOut)
	case "status":
		return runHostStatus(args[1:], out)
	case "plan-storage":
		if len(args) != 1 {
			return errors.New("usage: boetticher host plan-storage")
		}
		return runControllerStorage([]string{"plan"}, out)
	case "teardown":
		return runHostTeardown(args[1:], input, out)
	case "reboot":
		return runHostReboot(args[1:], out)
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

func runHostCreateIdentity(args []string, out io.Writer) error {
	if len(args) != 0 {
		return errors.New("usage: boetticher host create-identity")
	}
	if err := requireControllerReady(); err != nil {
		return err
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
}

func runHostShowPublicKey(args []string, out io.Writer) error {
	if len(args) != 0 {
		return errors.New("usage: boetticher host show-public-key")
	}
	if err := requireControllerReady(); err != nil {
		return err
	}
	key, err := controllerhost.PublicKey()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, key)
	return err
}

func runHostImportHostKey(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("host import-host-key", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	address := fs.String("address", "", "verified Proxmox IPv4 address")
	key := fs.String("key", "", "public host key copied from the trusted Mac")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *address == "" || *key == "" {
		return errors.New("usage: boetticher host import-host-key --address IPv4 --key 'ssh-ed25519 ...'")
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
	ctx := context.Background()
	inventory, err := controllerhost.Collect(ctx, transport, *details)
	if err != nil {
		return err
	}
	baseline := false
	var baselineErr error
	var storagePlan controllerhost.StoragePlan
	var storageErr error
	var networkPlan controllerhost.NetworkPlan
	var networkErr error
	if config.Proxmox.Node != "" {
		baseline, baselineErr = controllerhost.CheckBaseline(ctx, transport)
		storagePlan, storageErr = controllerhost.DiscoverStorage(ctx, transport, config)
		networkPlan, networkErr = controllerhost.DiscoverNetwork(ctx, transport, config)
	}
	fmt.Fprintln(out, "Proxmox host")
	fmt.Fprintln(out, "PASS  Host trust         Established")
	fmt.Fprintf(out, "PASS  Controller access  %s\n", controllerhost.ConfigSummary(config))
	nodeOK := config.Proxmox.Node != "" && len(inventory.Nodes) == 1 && inventory.Nodes[0].Node == config.Proxmox.Node
	if nodeOK {
		fmt.Fprintf(out, "PASS  Enrollment         %s\n", config.Proxmox.Node)
	} else if config.Proxmox.Node == "" {
		fmt.Fprintln(out, "FAIL  Enrollment         Not configured")
	} else {
		observed := "none"
		if len(inventory.Nodes) > 0 {
			observed = inventory.Nodes[0].Node
		}
		fmt.Fprintf(out, "FAIL  Enrollment         expected %s, observed %s\n", config.Proxmox.Node, observed)
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
	if config.Proxmox.Node != "" && baselineErr == nil && baseline {
		fmt.Fprintln(out, "PASS  Host configuration Configured")
	} else {
		fmt.Fprintln(out, "FAIL  Host configuration Not configured")
	}
	storageOK := config.Proxmox.Node != "" && storageErr == nil && storagePlan.State == "exact"
	if storageOK {
		fmt.Fprintln(out, "PASS  Storage            boetticher-data")
	} else if config.Proxmox.Node == "" {
		fmt.Fprintln(out, "FAIL  Storage            Not configured")
	} else if storageErr != nil {
		fmt.Fprintf(out, "FAIL  Storage            %v\n", storageErr)
	} else {
		fmt.Fprintf(out, "FAIL  Storage            %s\n", storagePlan.Detail)
	}
	networkOK := config.Proxmox.Node != "" && networkErr == nil && networkPlan.State == "exact"
	if networkOK {
		fmt.Fprintln(out, "PASS  Internal network   vmbr1")
	} else if config.Proxmox.Node == "" {
		fmt.Fprintln(out, "FAIL  Internal network   Not configured")
	} else if networkErr != nil {
		fmt.Fprintf(out, "FAIL  Internal network   %v\n", networkErr)
	} else {
		fmt.Fprintf(out, "FAIL  Internal network   %s\n", networkPlan.Detail)
	}
	fmt.Fprintf(out, "      Physical LAB       %s\n", physicalLABStatus(networkPlan, networkErr))
	if *details {
		renderHostDetails(out, inventory)
	}
	if !nodeOK || !servicesOK || !baseline || !storageOK || !networkOK {
		fmt.Fprintln(out, "\nHost readiness: FAIL")
		return errors.New("Proxmox Host readiness failed")
	}
	fmt.Fprintln(out, "\nHost readiness: PASS")
	return nil
}

func physicalLABStatus(plan controllerhost.NetworkPlan, err error) string {
	if err != nil {
		return "Unknown: " + err.Error()
	}
	if plan.Config.PhysicalTrunk == "" {
		return "Virtual bridge path"
	}
	if plan.State == "exact" {
		return plan.Config.PhysicalTrunk + " attached"
	}
	return plan.Config.PhysicalTrunk + " not ready (" + plan.State + ")"
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
