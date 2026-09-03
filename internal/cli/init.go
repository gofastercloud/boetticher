package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/site"
)

func runInit(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site-dir", model.DefaultSiteDir, "private site repository directory")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	externalFirewall := fs.Bool("external-firewall", false, "bring your own external firewall; do not create lab-fw-01")
	storageProfile := fs.String("storage-profile", "single-disk", "fixed storage profile: single-disk or dedicated-data-disk")
	storageDevice := fs.String("storage-device", "", "stable /dev/disk/by-id device for dedicated-data-disk")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *storageProfile != "single-disk" && *storageProfile != "dedicated-data-disk" {
		return fmt.Errorf("unsupported storage profile %q", *storageProfile)
	}
	if *storageProfile == "dedicated-data-disk" {
		if err := model.ValidateStableDevice(*storageDevice); err != nil {
			return err
		}
	} else if *storageDevice != "" {
		return errors.New("--storage-device is only valid with --storage-profile dedicated-data-disk")
	}
	created, err := site.Init(*siteDir, *ageIdentity, *externalFirewall)
	if err != nil {
		return err
	}
	if *storageProfile == "dedicated-data-disk" {
		config := model.ConfigFromSite(created)
		config.StorageProfile = *storageProfile
		config.StorageDevice = *storageDevice
		created, err = site.ComposeConfig(*siteDir, config)
		if err != nil {
			return fmt.Errorf("configure dedicated storage: %w", err)
		}
		if err := site.SaveConfig(*siteDir, config); err != nil {
			return fmt.Errorf("save dedicated storage configuration: %w", err)
		}
	}
	revision, _ := created.Revision()
	if err := writeModelProjections(*siteDir, created); err != nil {
		return err
	}
	fmt.Fprintf(out, "Initialization: PASS private site repository created at %s\n", *siteDir)
	fmt.Fprintf(out, "Age identity: %s (outside Git)\n", model.ExpandUserPath(*ageIdentity))
	fmt.Fprintf(out, "Model: PASS revision %s\n", revision)
	fmt.Fprintf(out, "Gateway: PASS mode %s\n", created.Gateway.Mode)
	fmt.Fprintf(out, "Storage: PASS %s\n", created.StorageProfile)
	if created.StorageDevice != "" {
		fmt.Fprintf(out, "Storage device: %s\n", created.StorageDevice)
	}
	fmt.Fprintf(out, "Gateway upstream MAC: %s (create the matching upstream DHCP reservation)\n", created.Gateway.Upstream.MAC)
	if created.Gateway.Mode == model.GatewayModeExternal {
		fmt.Fprintln(out, "Physical network prerequisite: external mode requires a distinct physical vmbr1 trunk before bootstrap")
	}
	fmt.Fprintln(out, "Bootstrap prerequisite: independent Age recovery copy required before destructive bootstrap")
	fmt.Fprintln(out, "Next action: secure the independent Age recovery copy, then run boetticher enroll --site <site> --bootstrap-address ADDRESS")
	return nil
}
