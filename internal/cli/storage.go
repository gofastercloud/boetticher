package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/site"
	"github.com/gofastercloud/boetticher/internal/storage"
)

func runStorage(args []string, out interface{ Write([]byte) (int, error) }) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher storage status|initialize")
	}
	command := args[0]
	fs := flag.NewFlagSet("storage "+command, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	initialUser := fs.String("initial-user", "root", "initial Proxmox SSH user")
	knownHosts := fs.String("known-hosts", "", "optional SSH known-hosts file")
	confirmed := fs.Bool("confirmed", false, "confirm the fixed dedicated-disk initialization")
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
		return errors.New("dedicated storage initialization is destructive; repeat with --confirmed after reviewing the stable device")
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
