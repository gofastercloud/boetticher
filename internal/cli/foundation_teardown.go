package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

func runHostTeardown(args []string, input io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("host teardown", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	planOnly := fs.Bool("plan", false, "show the teardown plan without changing state")
	yes := fs.Bool("yes", false, "confirm ordinary Host removal")
	dataDisk := fs.String("data-disk", "", "exact stable data-disk identity to erase")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: boetticher host teardown [--plan] [--data-disk /dev/disk/by-id/DEVICE] [--yes]")
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
	if config.Proxmox.Node == "" {
		fmt.Fprintln(out, "Host configuration: NOT CONFIGURED")
		fmt.Fprintln(out, "Controller↔Proxmox SSH trust is preserved.")
		fmt.Fprintln(out, "No changes required.")
		return nil
	}
	ctx := context.Background()
	inventory, err := controllerhost.Collect(ctx, transport, false)
	if err != nil {
		return teardownFailure(out, "Host teardown could not inspect Proxmox.", err, "No Host state was changed.", "sudo boetticher host teardown --plan")
	}
	if len(inventory.Guests) != 0 {
		return teardownFailure(out, "Host teardown stopped.", fmt.Errorf("unexpected guests are present: %s", guestList(inventory.Guests)), "No Host state was changed.", "Remove or preserve the guests deliberately, then rerun the plan")
	}
	if config.Storage == nil || config.Storage.Device == "" {
		return teardownFailure(out, "Host teardown stopped.", errors.New("dedicated storage selection is absent from lab.yml"), "No Host state was changed.", "Inspect lab.yml and native storage before retrying")
	}
	storagePlan, err := controllerhost.DiscoverStorage(ctx, transport, config)
	if err != nil {
		return teardownFailure(out, "Host teardown could not inspect storage.", err, "No Host state was changed.", "sudo boetticher host teardown --plan")
	}
	storageState, storageDetail := controllerhost.StorageTeardownState(storagePlan)
	if storageState == "conflict" {
		return teardownFailure(out, "Host teardown stopped.", errors.New(storageDetail), "No Host state was changed.", "Inspect native LVM and Proxmox storage before retrying")
	}
	networkPlan, err := controllerhost.DiscoverNetwork(ctx, transport, config)
	if err != nil {
		return teardownFailure(out, "Host teardown could not inspect the internal network.", err, "No Host state was changed.", "sudo boetticher host teardown --plan")
	}
	if networkPlan.State != "exact" && networkPlan.State != "absent" {
		return teardownFailure(out, "Host teardown stopped.", fmt.Errorf("internal network is %s: %s", networkPlan.State, networkPlan.Detail), "No Host state was changed.", "Inspect vmbr1 before retrying")
	}
	baseline, baselineErr := controllerhost.CheckBaseline(ctx, transport)
	if baselineErr != nil {
		return teardownFailure(out, "Host teardown could not inspect the Host configuration.", baselineErr, "No Host state was changed.", "sudo boetticher host status")
	}
	renderHostTeardownPlan(out, config, storagePlan, storageState, networkPlan, baseline)
	if *planOnly {
		return nil
	}
	if storageState != "absent" && *dataDisk != config.Storage.Device {
		return errors.New("Host teardown requires --data-disk with the exact configured stable path")
	}
	if !*yes {
		if input == nil {
			return errors.New("Host teardown requires --yes or an interactive confirmation")
		}
		answer, promptErr := promptYesNo(bufio.NewReader(input), out, "\nContinue? [y/N]: ", false)
		if promptErr != nil {
			return promptErr
		}
		if !answer {
			return errors.New("Host teardown cancelled")
		}
	}

	if networkPlan.State == "exact" {
		fresh, discoverErr := controllerhost.DiscoverNetwork(ctx, transport, config)
		if discoverErr != nil || fresh.State != "exact" {
			if discoverErr == nil {
				discoverErr = fmt.Errorf("internal network changed to %s: %s", fresh.State, fresh.Detail)
			}
			return teardownFailure(out, "Host teardown stopped before network removal.", discoverErr, "No Host state was changed.", "sudo boetticher host teardown --plan")
		}
		command, commandErr := controllerhost.NetworkTeardownCommand(fresh)
		if commandErr != nil {
			return teardownFailure(out, "Host teardown stopped before network removal.", commandErr, "No Host state was changed.", "sudo boetticher host teardown --plan")
		}
		if _, commandErr = transport.Run(ctx, command); commandErr != nil {
			return teardownFailure(out, "Host teardown incomplete.", commandErr, "Internal network removal was not verified.", "sudo boetticher host teardown --plan")
		}
		post, postErr := controllerhost.DiscoverNetwork(ctx, transport, config)
		if postErr != nil || post.State != "absent" || !sameManagementPath(fresh.Management, post.Management) {
			if postErr == nil {
				postErr = errors.New("vmbr1 removal or protected HOME management verification failed")
			}
			return teardownFailure(out, "Host teardown incomplete.", postErr, "vmbr1 removal was attempted; HOME protection was not fully verified.", "sudo boetticher host teardown --plan")
		}
		fmt.Fprintln(out, "Removed: vmbr1 and vmbr1 host IPv6 suppression")
	}

	if storageState != "absent" {
		fresh, discoverErr := controllerhost.DiscoverStorage(ctx, transport, config)
		if discoverErr != nil {
			return teardownFailure(out, "Host teardown stopped before storage removal.", discoverErr, "vmbr1 was removed; storage remains.", "sudo boetticher host teardown --plan")
		}
		freshState, freshDetail := controllerhost.StorageTeardownState(fresh)
		if freshState != "owned" && freshState != "owned-partial" {
			return teardownFailure(out, "Host teardown stopped before storage removal.", fmt.Errorf("storage changed to %s: %s", freshState, freshDetail), "vmbr1 was removed; storage remains.", "sudo boetticher host teardown --plan")
		}
		command, commandErr := controllerhost.StorageTeardownCommand(fresh, *dataDisk)
		if commandErr != nil {
			return teardownFailure(out, "Host teardown stopped before storage removal.", commandErr, "vmbr1 was removed; storage remains.", "sudo boetticher host teardown --plan")
		}
		if _, commandErr = transport.Run(ctx, command); commandErr != nil {
			return teardownFailure(out, "Host teardown incomplete.", commandErr, "vmbr1 was removed; storage teardown is incomplete.", "sudo boetticher host teardown --plan --data-disk "+*dataDisk)
		}
		post, postErr := controllerhost.DiscoverStorage(ctx, transport, config)
		if postErr != nil {
			return teardownFailure(out, "Host teardown incomplete.", postErr, "Storage removal was attempted but could not be verified.", "sudo boetticher host teardown --plan --data-disk "+*dataDisk)
		}
		postState, postDetail := controllerhost.StorageTeardownState(post)
		if postState != "absent" {
			return teardownFailure(out, "Host teardown incomplete.", fmt.Errorf("storage remains %s: %s", postState, postDetail), "vmbr1 was removed; storage teardown is incomplete.", "sudo boetticher host teardown --plan --data-disk "+*dataDisk)
		}
		fmt.Fprintln(out, "Removed: boetticher-data, boetticher-vg, thin pool data, and Timetec PV metadata")
	}

	if baseline {
		if _, commandErr := transport.Run(ctx, controllerhost.HostBaselineTeardownCommand()); commandErr != nil {
			return teardownFailure(out, "Host teardown incomplete.", commandErr, "Network and storage were removed; Host configuration remains.", "sudo boetticher host teardown --plan")
		}
		prepared, checkErr := controllerhost.CheckBaseline(ctx, transport)
		if checkErr != nil || prepared {
			if checkErr == nil {
				checkErr = errors.New("owned host baseline configuration remains")
			}
			return teardownFailure(out, "Host teardown incomplete.", checkErr, "Network and storage were removed; Host configuration remains.", "sudo boetticher host teardown --plan")
		}
		fmt.Fprintln(out, "Removed: safely owned host-baseline configuration")
	}

	config.Proxmox.Node = ""
	config.Storage = nil
	config.Network = nil
	if err := controllerhost.SaveConfig(config); err != nil {
		return teardownFailure(out, "Host teardown incomplete.", err, "Remote Host state was removed; trust and local enrollment state need review.", "sudo boetticher host teardown --plan")
	}
	fmt.Fprintln(out, "Removed: host enrollment, storage selection, and network selection")
	fmt.Fprintln(out, "Preserved: Controller↔Proxmox SSH trust and HOME management")
	fmt.Fprintln(out, "Host teardown: PASS")
	return nil
}

func renderHostTeardownPlan(out io.Writer, config controllerhost.LabConfig, storage controllerhost.StoragePlan, storageState string, network controllerhost.NetworkPlan, baseline bool) {
	fmt.Fprintln(out, "Host teardown")
	fmt.Fprintln(out, "\nPRESERVE\n\n  Controller identity\n  Proxmox host trust\n  Mac recovery access\n  Proxmox installation\n  HOME management\n    vmbr0\n    nic0\n    192.168.4.5\n    default route 192.168.4.1")
	fmt.Fprintf(out, "  Boot disk\n    %s\n", firstStableID(storage.BootDisk))
	fmt.Fprintln(out, "\nREMOVE")
	if network.State == "exact" {
		fmt.Fprintln(out, "\n  Internal network\n    vmbr1\n    vmbr1 IPv6 suppression")
	} else {
		fmt.Fprintln(out, "\n  Internal network\n    already absent")
	}
	if storageState == "absent" {
		fmt.Fprintln(out, "\n  Dedicated storage\n    already absent")
	} else {
		fmt.Fprintf(out, "\n  Dedicated storage\n    Proxmox storage: boetticher-data\n    VG: boetticher-vg\n    thin pool: data\n    PV: Timetec MS21\n    stable ID: %s\n", config.Storage.Device)
	}
	fmt.Fprintf(out, "\n  Host enrollment\n    %s\n", config.Proxmox.Node)
	if baseline {
		fmt.Fprintln(out, "\n  Safely removable Boetticher-owned host baseline configuration")
	}
	if storageState != "absent" {
		fmt.Fprintf(out, "\nWARNING\n\n  The dedicated data disk will be erased.\n  Exact binding required: --data-disk %s\n", config.Storage.Device)
	}
	fmt.Fprintln(out, "\nController↔Proxmox SSH trust WILL BE PRESERVED.")
}

func teardownFailure(out io.Writer, heading string, detail error, applied, next string) error {
	fmt.Fprintf(out, "\n%s\n\nRemoved or applied:\n  %s\n\nFailed:\n  %v\n\nPreserved:\n  Controller↔Proxmox SSH trust\n  HOME management\n  Proxmox boot storage\n\nNext:\n  %s\n", heading, applied, detail, next)
	return detail
}

func guestList(guests []controllerhost.Guest) string {
	values := make([]string, 0, len(guests))
	for _, guest := range guests {
		values = append(values, fmt.Sprintf("%d:%s", guest.VMID, guest.Name))
	}
	return strings.Join(values, ", ")
}
