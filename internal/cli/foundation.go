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
	if len(args) != 0 {
		return errors.New("usage: boetticher foundation status")
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
	}
	config, configErr := controllerhost.LoadConfig()
	if configErr != nil {
		fmt.Fprintln(out, "FAIL  Proxmox            Enrollment missing")
		fmt.Fprintln(out, "FAIL  Host baseline      Not available")
		fmt.Fprintln(out, "FAIL  Dedicated storage  Not available")
		fmt.Fprintln(out, "FAIL  Internal network   Not available")
		fmt.Fprintln(out, "\nPhysical LAB trunk      Not configured")
		fmt.Fprintln(out, "Platform guests          Not deployed")
		fmt.Fprintln(out, "Foundation readiness: FAIL")
		return configErr
	}
	transport, transportErr := controllerhost.TransportFor(config)
	hostOK := false
	storageOK := false
	networkOK := false
	if transportErr == nil {
		hostInventory, hostErr := controllerhost.Collect(context.Background(), transport, false)
		hostOK = hostErr == nil && len(hostInventory.Nodes) == 1 && hostInventory.Nodes[0].Node == config.Proxmox.Node
		baseline, _ := controllerhost.CheckBaseline(context.Background(), transport)
		hostOK = hostOK && baseline
		storagePlan, storageErr := controllerhost.DiscoverStorage(context.Background(), transport, config)
		storageOK = storageErr == nil && storagePlan.State == "exact"
		networkPlan, networkErr := controllerhost.DiscoverNetwork(context.Background(), transport, config)
		networkOK = networkErr == nil && networkPlan.State == "exact"
	}
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
