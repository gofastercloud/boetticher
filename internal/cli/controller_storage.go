package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

func shouldRunControllerStorage(args []string) bool {
	if len(args) == 0 {
		return false
	}
	return args[0] == "plan" || args[0] == "status" || args[0] == "initialize"
}

func runControllerStorage(args []string, out io.Writer) error {
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
	switch args[0] {
	case "plan":
		if len(args) != 1 {
			return errors.New("usage: boetticher storage plan")
		}
		plan, err := controllerhost.DiscoverStorage(context.Background(), transport, config)
		if err != nil {
			return err
		}
		renderStoragePlan(out, plan)
		return nil
	case "status":
		fs := flag.NewFlagSet("storage status", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
			return errors.New("usage: boetticher storage status")
		}
		return runControllerStorageStatus(context.Background(), transport, config, out)
	case "initialize":
		return runControllerStorageInitialize(args[1:], transport, config, out)
	default:
		return fmt.Errorf("unknown controller storage command %q", args[0])
	}
}

func runControllerStorageStatus(ctx context.Context, transport controllerhost.Transport, config controllerhost.LabConfig, out io.Writer) error {
	plan, err := controllerhost.DiscoverStorage(ctx, transport, config)
	if err != nil {
		renderStorageFailure(out, "Storage discovery failed.", err.Error(), "No storage change was applied.", "sudo boetticher storage status")
		return err
	}
	fmt.Fprintln(out, "Dedicated storage")
	if plan.Selected == nil || plan.State != "exact" {
		fmt.Fprintf(out, "FAIL  Data disk       %s\n", plan.Detail)
		fmt.Fprintln(out, "\nStorage readiness: FAIL")
		return errors.New("dedicated storage is not initialized and healthy")
	}
	disk := plan.Selected
	fmt.Fprintf(out, "PASS  Data disk       %s\n", diskLabel(*disk))
	identity := "unknown"
	if config.Storage != nil {
		identity = config.Storage.Device
	} else if len(disk.StableIDs) == 1 {
		identity = disk.StableIDs[0]
	}
	fmt.Fprintf(out, "PASS  Stable identity %s\n", identity)
	fmt.Fprintln(out, "PASS  LVM PV          Active")
	fmt.Fprintln(out, "PASS  Volume group    boetticher-vg")
	fmt.Fprintln(out, "PASS  Thin pool       data")
	fmt.Fprintln(out, "PASS  Proxmox storage boetticher-data")
	fmt.Fprintln(out, "PASS  Content types   images, rootdir")
	fmt.Fprintln(out, "\nStorage readiness: PASS")
	return nil
}

func runControllerStorageInitialize(args []string, transport controllerhost.Transport, config controllerhost.LabConfig, out io.Writer) error {
	fs := flag.NewFlagSet("storage initialize", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	device := fs.String("device", "", "exact stable /dev/disk/by-id device")
	confirm := fs.Bool("confirm", false, "confirm erasing the freshly validated selected device")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: boetticher storage initialize --device /dev/disk/by-id/DEVICE --confirm")
	}
	ctx := context.Background()
	plan, err := controllerhost.DiscoverStorage(ctx, transport, config)
	if err != nil {
		return err
	}
	if plan.State == "exact" {
		if *device != "" && (plan.Selected == nil || !hasStableID(plan.Selected.StableIDs, *device)) {
			return errors.New("--device does not match the exact owned storage identity")
		}
		if config.Storage == nil && plan.Selected != nil {
			config.Storage = &controllerhost.StorageConfig{Profile: controllerhost.StorageProfile, Device: firstStableID(*plan.Selected), GuestStorage: controllerhost.GuestStorageID}
			if err := controllerhost.SaveConfig(config); err != nil {
				renderStorageFailure(out, "Storage is initialized, but controller configuration was not saved.", err.Error(), "Native storage was preserved.", "sudo boetticher storage status")
				return fmt.Errorf("storage is initialized but could not save controller selection: %w", err)
			}
		}
		fmt.Fprintln(out, "Storage already initialized and healthy.")
		fmt.Fprintln(out, "No changes required.")
		return nil
	}
	if plan.State != "empty" || plan.Selected == nil {
		renderStoragePlan(out, plan)
		return fmt.Errorf("storage initialization is not eligible: %s", plan.Detail)
	}
	if *device == "" {
		return errors.New("first initialization requires --device with the exact stable /dev/disk/by-id path")
	}
	if !hasStableID(plan.Selected.StableIDs, *device) {
		return errors.New("--device does not match the freshly discovered candidate stable identity")
	}
	if !*confirm {
		renderStoragePlan(out, plan)
		return errors.New("storage initialization is destructive; repeat with --confirm after reviewing the exact device")
	}
	// Re-discover immediately before crossing the destructive boundary.
	fresh, err := controllerhost.DiscoverStorage(ctx, transport, config)
	if err != nil {
		renderStorageFailure(out, "Storage revalidation failed.", err.Error(), "No disk was changed.", "sudo boetticher storage plan")
		return err
	}
	if fresh.State != "empty" || fresh.Selected == nil || !hasStableID(fresh.Selected.StableIDs, *device) {
		err := errors.New("candidate storage changed during validation; refusing initialization")
		renderStorageFailure(out, "Storage initialization stopped.", err.Error(), "No disk was changed.", "sudo boetticher storage plan")
		return err
	}
	command, err := controllerhost.InitializationCommand(fresh)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Storage initialization: RUNNING\n  Device: %s\n  Model: %s\n", *device, diskLabel(*fresh.Selected))
	if _, err := transport.Run(ctx, command); err != nil {
		renderStorageFailure(out, "Storage initialization failed.", err.Error(), "No verified storage layout was established.", "sudo boetticher storage status")
		return fmt.Errorf("storage initialization failed: %w", err)
	}
	config.Storage = &controllerhost.StorageConfig{Profile: controllerhost.StorageProfile, Device: *device, GuestStorage: controllerhost.GuestStorageID}
	if err := controllerhost.SaveConfig(config); err != nil {
		renderStorageFailure(out, "Storage initialized, but controller configuration was not saved.", err.Error(), "Native storage was preserved.", "sudo boetticher storage status")
		return fmt.Errorf("storage initialized but could not save controller selection: %w", err)
	}
	fmt.Fprintln(out, "Storage initialization: PASS")
	return nil
}

func renderStorageFailure(out io.Writer, heading, detail, applied, next string) {
	fmt.Fprintf(out, "\n%s\n\nApplied:\n  %s\n\nFailure detail:\n  %s\n\nPreserved:\n  Proxmox boot disk\n  Existing LVM and guests\n  Network configuration\n\nNext:\n  %s\n", heading, applied, detail, next)
}

func renderStoragePlan(out io.Writer, plan controllerhost.StoragePlan) {
	fmt.Fprintln(out, "Dedicated data storage")
	fmt.Fprintf(out, "\nBoot disk — PROTECTED\n  Model:     %s\n  Stable ID: %s\n  Size:      %s\n  Use:       Running Proxmox root/swap\n", plan.BootDisk.Model, firstStableID(plan.BootDisk), formatDiskSize(plan.BootDisk.Size))
	if len(plan.Candidates) > 0 {
		fmt.Fprintln(out, "\nCandidate data disk(s)")
		for _, disk := range plan.Candidates {
			fmt.Fprintf(out, "  Model:     %s\n  Serial:    %s\n  Stable ID: %s\n  Size:      %s\n  Partitions: none\n  Filesystems: none\n  Mounts:      none\n  LVM:         none\n  Proxmox use: none\n", disk.Model, disk.Serial, firstStableID(disk), formatDiskSize(disk.Size))
		}
	} else {
		fmt.Fprintf(out, "\nNo empty candidate: %s\n", plan.Detail)
		if plan.State == "exact" && plan.Selected != nil {
			fmt.Fprintf(out, "  Existing owned disk: %s\n", firstStableID(*plan.Selected))
		}
	}
	fmt.Fprintln(out, "\nProposed storage\n  ID:        boetticher-data\n  Type:      LVM-thin\n  VG:        boetticher-vg\n  Thin pool: data")
	if plan.Selected != nil && plan.State == "empty" {
		fmt.Fprintf(out, "\nWARNING: initialization will permanently erase all data on:\n  %s\n\nNothing else will be changed.\n\nNext:\n  sudo boetticher storage initialize --device %s --confirm\n", firstStableID(*plan.Selected), firstStableID(*plan.Selected))
	} else if plan.State != "exact" {
		fmt.Fprintf(out, "\nStorage state: %s\n", plan.Detail)
	}
}

func diskLabel(disk controllerhost.Disk) string {
	if disk.Model != "" {
		return strings.TrimSpace(disk.Model)
	}
	return "unknown model"
}

func firstStableID(disk controllerhost.Disk) string {
	if len(disk.StableIDs) == 0 {
		return "none"
	}
	return disk.StableIDs[0]
}

func hasStableID(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func formatDiskSize(size uint64) string {
	if size == 0 {
		return "unknown"
	}
	return fmt.Sprintf("%.1f GB", float64(size)/(1000*1000*1000))
}
