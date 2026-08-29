package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/site"
	"github.com/gofastercloud/boetticher/internal/storage"
)

func runStorage(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher storage status|initialize")
	}
	command := args[0]
	fs := flag.NewFlagSet("storage "+command, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	initialUser := fs.String("initial-user", "root", "initial Proxmox SSH user")
	knownHosts := fs.String("known-hosts", "", "optional SSH known-hosts file")
	live := fs.Bool("live", false, "inspect the configured storage over the Proxmox SSH path")
	confirmed := fs.Bool("storage-confirmed", false, "confirm the fixed dedicated-disk initialization")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	plan, err := storage.PlanFromSite(s)
	if err != nil {
		return err
	}
	if command == "status" {
		fmt.Fprintf(out, "Storage\n  Profile     %s\n  Device      %s\n  Guest       %s\n  Backup      %s\n  Mount       %s\n", plan.Profile, valueOrPlaceholder(plan.Device), plan.GuestStorage, plan.BackupStorage, plan.BackupMount)
		if plan.Profile == "dedicated-data-disk" {
			fmt.Fprintf(out, "  Layout      %s / %s / %s\n", plan.VolumeGroup, plan.ThinPool, plan.BackupLV)
			if *live {
				if s.BootstrapAddress == "" {
					return errors.New("bootstrap endpoint is not configured")
				}
				command, commandErr := storage.StatusCommand(plan.Device)
				if commandErr != nil {
					return commandErr
				}
				data, runErr := (proxmox.SSHRunner{KnownHosts: *knownHosts}).Run(context.Background(), s.BootstrapAddress, *initialUser, command)
				if runErr != nil {
					return runErr
				}
				status, parseErr := storage.ParseStatus(string(data))
				if parseErr != nil {
					return parseErr
				}
				fmt.Fprintf(out, "  Live        device=%s path=%s filesystem=%s mount=%s guest=%s backup=%s\n", status.Device, status.DevicePath, status.Filesystem, status.Mount, status.GuestStorage, status.BackupStorage)
				if status.Capacity != "" {
					fmt.Fprintf(out, "  Capacity    %s\n", status.Capacity)
				}
			}
		}
		return nil
	}
	if command != "initialize" {
		return fmt.Errorf("unknown storage command %q", command)
	}
	if plan.Profile != "dedicated-data-disk" {
		return errors.New("storage initialize is only needed for dedicated-data-disk; single-disk is already available")
	}
	if s.BootstrapAddress == "" {
		return errors.New("bootstrap endpoint is not configured")
	}
	if !*confirmed {
		return errors.New("dedicated storage initialization is destructive; repeat with --storage-confirmed after reviewing the stable device")
	}
	runner := proxmox.SSHRunner{KnownHosts: *knownHosts}
	if err := storage.Initialize(context.Background(), runner, s.BootstrapAddress, *initialUser, plan.Device, true); err != nil {
		return err
	}
	if err := writeModelProjections(*siteDir, s); err != nil {
		return err
	}
	fmt.Fprintf(out, "Dedicated storage initialized: %s\n", plan.Device)
	return nil
}
