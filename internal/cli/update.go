package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/pathguard"
	"github.com/gofastercloud/boetticher/internal/site"
)

func runUpdate(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	bundle := fs.String("bundle", "", "import an authenticated offline release bundle")
	dryRun := fs.Bool("dry-run", false, "validate and show the desired-state update without writing")
	confirm := fs.Bool("confirm", false, "authorize the desired-state update")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dryRun && *confirm {
		return errors.New("--dry-run and --confirm cannot be used together")
	}
	if *bundle != "" {
		if *dryRun || *confirm {
			return errors.New("--bundle cannot be combined with --dry-run or --confirm")
		}
		return runBundleImport([]string{*bundle, "--site", *siteDir}, out)
	}

	original, err := pathguard.ReadFile(filepath.Join(*siteDir, "site.yml"))
	if err != nil {
		return fmt.Errorf("Problem: read site.yml: %w", err)
	}
	config, err := site.LoadConfig(*siteDir)
	if err != nil {
		return fmt.Errorf("Problem: validate update: %w", err)
	}
	originalSite, err := site.ComposeConfig(*siteDir, config)
	if err != nil {
		return fmt.Errorf("Problem: compose existing desired state: %w", err)
	}
	fromVersion := config.PlatformVersion
	if fromVersion == "" {
		fromVersion = "current configuration"
	}
	config.APIVersion = model.APIVersion
	config.SchemaVersion = model.SchemaVersion
	config.PlatformVersion = model.PlatformVersion
	if err := config.Validate(); err != nil {
		return fmt.Errorf("Problem: the updated desired state is invalid: %w", err)
	}
	resolved, err := site.ComposeConfig(*siteDir, config)
	if err != nil {
		return fmt.Errorf("Problem: compose updated desired state: %w", err)
	}

	fmt.Fprintf(out, "Update plan: platform %s -> %s; schema remains %d; model revision %s\n", fromVersion, model.PlatformVersion, model.SchemaVersion, updateRevision(resolved))
	if *dryRun {
		fmt.Fprintln(out, "Dry run: no desired or generated state was changed; deploy has not been called.")
		return nil
	}
	if !*confirm {
		return errors.New("HOLD: review the update plan and rerun with --confirm")
	}

	if err := site.SaveConfig(*siteDir, config); err != nil {
		return fmt.Errorf("Problem: save updated desired configuration: %w", err)
	}
	if err := writeModelProjections(*siteDir, resolved); err != nil {
		return rollbackUpdate(*siteDir, original, originalSite, fmt.Errorf("refresh generated projections: %w", err))
	}
	fmt.Fprintln(out, "Updated desired configuration atomically. No deployment was performed; run boetticher deploy, then boetticher status.")
	return nil
}

func rollbackUpdate(dir string, originalConfig []byte, originalSite model.Site, cause error) error {
	if err := site.SaveConfigBytes(dir, originalConfig); err != nil {
		return fmt.Errorf("Problem: %w; restore desired configuration: %v", cause, err)
	}
	if err := writeModelProjections(dir, originalSite); err != nil {
		return fmt.Errorf("Problem: %w; desired configuration was restored but generated projections could not be restored: %v", cause, err)
	}
	return fmt.Errorf("Problem: %w; desired configuration and generated projections were restored", cause)
}

func updateRevision(s model.Site) string {
	revision, err := s.Revision()
	if err != nil {
		return "unavailable"
	}
	return revision
}
