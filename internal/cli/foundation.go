package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/gofastercloud/boetticher/internal/controller"
	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

func runFoundation(args []string, out io.Writer) error {
	return runFoundationWithInput(args, nil, out)
}

func runFoundationWithInput(args []string, input io.Reader, out io.Writer) error {
	if len(args) != 0 {
		if len(args) == 1 && args[0] == "converge" {
			return runFoundationConverge(out)
		}
		if len(args) >= 1 && args[0] == "teardown" {
			return runFoundationTeardown(args[1:], input, out)
		}
		if len(args) != 1 || args[0] != "status" {
			return errors.New("usage: boetticher foundation status|converge|teardown")
		}
	}
	checks, err := controller.RunStatus(context.Background(), controller.StatusOptions{})
	if err != nil {
		return err
	}
	controllerOK := true
	for _, check := range checks {
		if !check.Passed {
			controllerOK = false
			break
		}
	}
	fmt.Fprintln(out, "Boetticher foundation")
	if controllerOK {
		fmt.Fprintln(out, "PASS  Controller         Ready")
	} else {
		fmt.Fprintln(out, "FAIL  Controller         Not ready")
		fmt.Fprintln(out, "\nProxmox checks stopped because the Controller is not ready.")
		fmt.Fprintln(out, "Physical LAB trunk      Not configured")
		fmt.Fprintln(out, "Platform guests          Not deployed")
		fmt.Fprintln(out, "Foundation readiness: FAIL")
		return errors.New("controller is not ready")
	}
	config, configErr := controllerhost.LoadConfig()
	if configErr != nil {
		fmt.Fprintln(out, "FAIL  Proxmox            Enrollment missing")
		fmt.Fprintln(out, "\nPhysical LAB trunk      Not configured")
		fmt.Fprintln(out, "Platform guests          Not deployed")
		fmt.Fprintln(out, "Foundation readiness: FAIL")
		return configErr
	}
	transport, transportErr := controllerhost.TransportFor(config)
	if transportErr != nil {
		fmt.Fprintf(out, "FAIL  Proxmox            %v\n", transportErr)
		fmt.Fprintln(out, "\nProxmox checks stopped because the enrolled transport is unavailable.")
		fmt.Fprintln(out, "Physical LAB trunk      Not configured")
		fmt.Fprintln(out, "Platform guests          Not deployed")
		fmt.Fprintln(out, "Foundation readiness: FAIL")
		return transportErr
	}
	hostInventory, hostErr := controllerhost.Collect(context.Background(), transport, false)
	if hostErr != nil {
		fmt.Fprintf(out, "FAIL  Proxmox            enrolled host unavailable: %v\n", hostErr)
		fmt.Fprintln(out, "\nHost, storage, and network checks stopped because Proxmox could not be reached.")
		fmt.Fprintln(out, "Physical LAB trunk      Not configured")
		fmt.Fprintln(out, "Platform guests          Not deployed")
		fmt.Fprintln(out, "Foundation readiness: FAIL")
		return hostErr
	}
	if config.Proxmox.Node == "" {
		fmt.Fprintln(out, "PASS  Proxmox trust     Established")
		fmt.Fprintln(out, "\nHost enrollment       Not configured")
		fmt.Fprintln(out, "Host baseline          Not configured")
		fmt.Fprintln(out, "Dedicated storage     Not configured")
		fmt.Fprintln(out, "Internal network      Not configured")
		fmt.Fprintln(out, "\nFoundation readiness: NOT CONFIGURED\n\nNext:\n  sudo boetticher host enroll root@192.168.4.5")
		return nil
	}
	hostOK := len(hostInventory.Nodes) == 1 && hostInventory.Nodes[0].Node == config.Proxmox.Node
	baseline, baselineErr := controllerhost.CheckBaseline(context.Background(), transport)
	hostOK = hostOK && baselineErr == nil && baseline
	storagePlan, storageErr := controllerhost.DiscoverStorage(context.Background(), transport, config)
	storageOK := storageErr == nil && storagePlan.State == "exact"
	networkPlan, networkErr := controllerhost.DiscoverNetwork(context.Background(), transport, config)
	networkOK := networkErr == nil && networkPlan.State == "exact"
	if hostOK {
		fmt.Fprintln(out, "PASS  Proxmox            Enrolled and reachable")
		fmt.Fprintln(out, "PASS  Host baseline      Prepared")
	} else {
		fmt.Fprintln(out, "FAIL  Proxmox            Enrolled host check failed")
		fmt.Fprintln(out, "FAIL  Host baseline      Not ready")
	}
	if storageOK {
		fmt.Fprintln(out, "PASS  Dedicated storage  boetticher-data")
	} else {
		fmt.Fprintln(out, "FAIL  Dedicated storage  Not ready")
	}
	if networkOK {
		fmt.Fprintln(out, "PASS  Internal network   vmbr1")
	} else {
		fmt.Fprintln(out, "FAIL  Internal network   Not ready")
	}
	fmt.Fprintln(out, "Physical LAB trunk      Not configured")
	fmt.Fprintln(out, "Platform guests          Not deployed")
	if controllerOK && hostOK && storageOK && networkOK {
		fmt.Fprintln(out, "Foundation readiness: PASS\nNext:\n  Deploy the base platform.")
		return nil
	}
	fmt.Fprintln(out, "Foundation readiness: FAIL")
	return errors.New("Boetticher foundation is not ready")
}

// runFoundationConverge is the guided form of the explicit foundation
// commands. It only performs read-only convergence; trust and destructive
// storage/network decisions remain explicit ceremonies.
func runFoundationConverge(out io.Writer) error {
	checks, err := controller.RunStatus(context.Background(), controller.StatusOptions{})
	if err != nil {
		return err
	}
	for _, check := range checks {
		if !check.Passed {
			fmt.Fprintf(out, "Controller            failed: %s\nNext:\n  sudo boetticher controller bootstrap --operator pi --confirm-key-login\n", check.Detail)
			return errors.New("controller is not ready")
		}
	}
	fmt.Fprintln(out, "Controller            healthy")
	config, err := controllerhost.LoadConfig()
	if err != nil {
		fmt.Fprintf(out, "Proxmox enrollment    required: %v\nNext:\n  sudo boetticher host enroll root@PROXMOX_HOME_IP\n", err)
		return err
	}
	transport, err := controllerhost.TransportFor(config)
	if err != nil {
		return err
	}
	if config.Proxmox.Node == "" {
		if _, err := transport.Run(context.Background(), "hostname"); err != nil {
			fmt.Fprintf(out, "Proxmox trust         failed: %v\n", err)
			return err
		}
		fmt.Fprintln(out, "Proxmox trust         established")
		fmt.Fprintln(out, "Host enrollment       required")
		fmt.Fprintln(out, "Next:\n  sudo boetticher host enroll root@192.168.4.5")
		return errors.New("host enrollment is required")
	}
	ctx := context.Background()
	inventory, err := controllerhost.Collect(ctx, transport, false)
	if err != nil {
		fmt.Fprintf(out, "Proxmox enrollment    failed: %v\n", err)
		return err
	}
	if len(inventory.Nodes) != 1 || inventory.Nodes[0].Node != config.Proxmox.Node {
		return fmt.Errorf("Proxmox node identity mismatch: expected %s", config.Proxmox.Node)
	}
	baseline, baselineErr := controllerhost.CheckBaseline(ctx, transport)
	if baselineErr != nil || !baseline {
		fmt.Fprintln(out, "Proxmox enrollment    healthy")
		fmt.Fprintln(out, "Host baseline        requires approval")
		fmt.Fprintln(out, "Next:\n  sudo boetticher host prepare")
		return errors.New("host baseline requires explicit preparation")
	}
	fmt.Fprintln(out, "Proxmox enrollment    healthy")
	fmt.Fprintln(out, "Host baseline         healthy")
	storagePlan, err := controllerhost.DiscoverStorage(ctx, transport, config)
	if err != nil {
		return err
	}
	if storagePlan.State != "exact" {
		renderStoragePlan(out, storagePlan)
		if storagePlan.State == "empty" && storagePlan.Selected != nil {
			fmt.Fprintln(out, "Dedicated storage requires approval; no disk was changed.")
		}
		return fmt.Errorf("dedicated storage is not ready: %s", storagePlan.Detail)
	}
	fmt.Fprintln(out, "Dedicated storage    healthy")
	networkPlan, err := controllerhost.DiscoverNetwork(ctx, transport, config)
	if err != nil {
		return err
	}
	if networkPlan.State != "exact" {
		renderNetworkPlan(out, networkPlan)
		if networkPlan.State == "adoptable" {
			fmt.Fprintln(out, "Next:\n  sudo boetticher network configure --adopt-existing")
		} else if networkPlan.State == "absent" {
			fmt.Fprintln(out, "Next:\n  sudo boetticher network configure")
		}
		return fmt.Errorf("internal network is not ready: %s", networkPlan.Detail)
	}
	fmt.Fprintln(out, "Internal network     healthy")
	fmt.Fprintln(out, "\nNo changes required.")
	return nil
}
