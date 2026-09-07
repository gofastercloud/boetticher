package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/controllerstatus"
)

// runHostApply is the single Host mutation entry point. The individual
// baseline, storage, and network operations remain owned by their focused
// packages; this function only gives them one safe operator lifecycle.
func runHostApply(args []string, input io.Reader, out, errOut io.Writer) (err error) {
	fs := flag.NewFlagSet("host apply", flag.ContinueOnError)
	fs.SetOutput(errOut)
	yes := fs.Bool("yes", false, "approve ordinary Host changes")
	dataDisk := fs.String("data-disk", "", "exact stable /dev/disk/by-id device for dedicated data storage")
	adoptNetwork := fs.Bool("adopt-existing-network", false, "approve adoption of a compatible existing internal bridge")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: boetticher host apply [--data-disk /dev/disk/by-id/DEVICE] [--adopt-existing-network] [--yes]")
	}
	if err := requireControllerReady(); err != nil {
		return err
	}
	config, err := controllerhost.LoadConfig()
	if err != nil {
		return err
	}
	if config.Proxmox.Node == "" {
		return errors.New("host enrollment is required before host apply")
	}
	transport, err := hostTransport(config)
	if err != nil {
		return err
	}
	controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-start", Name: "host apply", Steps: 5})
	defer func() {
		if err != nil {
			controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-failure", Name: "host apply", Detail: err.Error()})
			return
		}
		controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-success", Name: "host apply"})
	}()
	ctx := context.Background()
	var promptReader *bufio.Reader
	prompt := func(message string) error {
		if *yes {
			return nil
		}
		if input == nil {
			return errors.New("host apply requires --yes or an interactive confirmation")
		}
		if promptReader == nil {
			promptReader = bufio.NewReader(input)
		}
		answer, err := promptYesNo(promptReader, out, message, false)
		if err != nil {
			return err
		}
		if !answer {
			return errors.New("host apply cancelled")
		}
		return nil
	}
	changed := false

	baseline, baselineErr := controllerhost.CheckBaseline(ctx, transport)
	if baselineErr != nil || !baseline {
		if _, err := controllerhost.Collect(ctx, transport, false); err != nil {
			return fmt.Errorf("revalidate Proxmox Host before apply: %w", err)
		}
		fmt.Fprintln(out, "Applying Host configuration...")
		fmt.Fprintln(out, "\n  Repository policy      current after apply")
		fmt.Fprintln(out, "  Required packages      current after apply")
		fmt.Fprintln(out, "  Headless operation     current after apply")
		if err := prompt("\nContinue? [y/N]: "); err != nil {
			return err
		}
		controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-progress", Name: "host apply", CurrentStep: 1, TotalSteps: 5, Detail: "Verifying Host access"})
		applyCtx, cancel := context.WithTimeout(ctx, 20*time.Minute)
		err := controllerhost.RunPrepare(applyCtx, config, transport, io.Discard)
		if err == nil {
			baseline, err = controllerhost.CheckBaseline(applyCtx, transport)
			if err == nil && !baseline {
				err = errors.New("Host baseline verification failed")
			}
		}
		cancel()
		if err != nil {
			fmt.Fprintf(out, "\nHost apply failed.\n\nPreserved:\n  Existing guests\n  Storage\n  Network interfaces\n  IP addresses\n  Controller SSH identity\n\nNext:\n  sudo boetticher host status\n")
			return err
		}
		fmt.Fprintln(out, "Host configuration: PASS")
		controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-progress", Name: "host apply", CurrentStep: 2, TotalSteps: 5, Detail: "Host OS configuration verified"})
		changed = true
	} else {
		controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-progress", Name: "host apply", CurrentStep: 2, TotalSteps: 5, Detail: "Host OS configuration already current"})
	}

	storagePlan, err := controllerhost.DiscoverStorage(ctx, transport, config)
	if err != nil {
		return fmt.Errorf("inspect Host storage before apply: %w", err)
	}
	if storagePlan.State == "exact" {
		if *dataDisk != "" && (storagePlan.Selected == nil || !hasStableID(storagePlan.Selected.StableIDs, *dataDisk)) {
			return errors.New("--data-disk does not match the exact owned storage identity")
		}
		if config.Storage == nil && storagePlan.Selected != nil {
			config.Storage = &controllerhost.StorageConfig{Profile: controllerhost.StorageProfile, Device: firstStableID(*storagePlan.Selected), GuestStorage: controllerhost.GuestStorageID}
			if err := controllerhost.SaveConfig(config); err != nil {
				return fmt.Errorf("Host storage is configured but desired configuration was not saved: %w", err)
			}
			changed = true
		}
		fmt.Fprintln(out, "Storage: configured")
	} else {
		renderStoragePlan(out, storagePlan)
		if storagePlan.State != "empty" || storagePlan.Selected == nil {
			return fmt.Errorf("Host storage configuration is not eligible: %s", storagePlan.Detail)
		}
		if *dataDisk == "" {
			return errors.New("dedicated data storage requires --data-disk with the exact stable path; no disk was changed")
		}
		if !hasStableID(storagePlan.Selected.StableIDs, *dataDisk) {
			return errors.New("--data-disk does not match the freshly discovered candidate stable identity")
		}
		if err := prompt("\nErase and configure this dedicated data disk? [y/N]: "); err != nil {
			return err
		}
		fresh, err := controllerhost.DiscoverStorage(ctx, transport, config)
		if err != nil {
			return fmt.Errorf("revalidate Host storage before apply: %w", err)
		}
		if fresh.State != "empty" || fresh.Selected == nil || !hasStableID(fresh.Selected.StableIDs, *dataDisk) {
			return errors.New("Host storage candidate changed during validation; no disk was changed")
		}
		command, err := controllerhost.InitializationCommand(fresh)
		if err != nil {
			return err
		}
		if _, err := transport.Run(ctx, command); err != nil {
			return fmt.Errorf("Host storage apply failed: %w", err)
		}
		config.Storage = &controllerhost.StorageConfig{Profile: controllerhost.StorageProfile, Device: *dataDisk, GuestStorage: controllerhost.GuestStorageID}
		if err := controllerhost.SaveConfig(config); err != nil {
			return fmt.Errorf("Host storage applied but desired configuration was not saved: %w", err)
		}
		fmt.Fprintln(out, "Storage: PASS configured")
		changed = true
	}
	controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-progress", Name: "host apply", CurrentStep: 3, TotalSteps: 5, Detail: "Storage configuration verified"})

	networkPlan, err := controllerhost.DiscoverNetwork(ctx, transport, config)
	if err != nil {
		return fmt.Errorf("inspect Host network before apply: %w", err)
	}
	if networkPlan.State == "exact" {
		if err := persistNetworkConfig(config, networkPlan.Config); err != nil {
			return err
		}
		fmt.Fprintln(out, "Internal network: configured")
	} else {
		renderNetworkPlan(out, networkPlan)
		if networkPlan.State == "adoptable" && !*adoptNetwork {
			return errors.New("Host network adoption requires --adopt-existing-network; no network change was applied")
		}
		if networkPlan.State != "absent" && !(networkPlan.State == "adoptable" && *adoptNetwork) {
			return fmt.Errorf("Host network configuration is not eligible: %s", networkPlan.Detail)
		}
		if err := prompt("\nConfigure the internal Host network? [y/N]: "); err != nil {
			return err
		}
		fresh, err := controllerhost.DiscoverNetwork(ctx, transport, config)
		if err != nil {
			return fmt.Errorf("revalidate Host network before apply: %w", err)
		}
		if fresh.State != networkPlan.State || !sameManagementPath(networkPlan.Management, fresh.Management) {
			return errors.New("Host network state changed during validation; no network change was applied")
		}
		command, err := controllerhost.NetworkConfigurationCommand(fresh, *adoptNetwork)
		if err != nil {
			return err
		}
		if _, err := transport.Run(ctx, command); err != nil {
			return fmt.Errorf("Host network apply failed: %w", err)
		}
		post, err := controllerhost.DiscoverNetwork(ctx, transport, config)
		if err != nil || post.State != "exact" || !sameManagementPath(fresh.Management, post.Management) {
			if err == nil {
				err = errors.New("protected HOME management-path verification failed")
			}
			return fmt.Errorf("Host network apply verification failed: %w", err)
		}
		if err := persistNetworkConfig(config, post.Config); err != nil {
			return fmt.Errorf("Host network applied but desired configuration was not saved: %w", err)
		}
		fmt.Fprintln(out, "Internal network: PASS configured")
		changed = true
	}
	controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-progress", Name: "host apply", CurrentStep: 4, TotalSteps: 5, Detail: "Network configuration verified"})
	if !changed {
		fmt.Fprintln(out, "No changes required.")
	}
	fmt.Fprintln(out, "Host apply: PASS")
	return nil
}
