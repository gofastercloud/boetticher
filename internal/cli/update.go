package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/pathguard"
	"github.com/gofastercloud/boetticher/internal/site"
)

func runUpdate(args []string, out interface{ Write([]byte) (int, error) }) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	dryRun := fs.Bool("dry-run", false, "validate and show the desired-state update without writing")
	confirm := fs.Bool("confirm", false, "authorize the desired-state update")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dryRun && *confirm {
		return errors.New("--dry-run and --confirm cannot be used together")
	}

	original, err := pathguard.ReadFile(filepath.Join(*siteDir, "site.yml"))
	if err != nil {
		return fmt.Errorf("Problem: read site.yml: %w", err)
	}
	config, err := site.LoadConfig(*siteDir)
	if err != nil {
		return fmt.Errorf("Problem: validate update: %w", err)
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
		_ = site.SaveConfigBytes(*siteDir, original)
		return fmt.Errorf("Problem: refresh generated projections: %w; desired configuration was restored", err)
	}
	if err := rebuildPortal(*siteDir, resolved); err != nil {
		_ = site.SaveConfigBytes(*siteDir, original)
		return fmt.Errorf("Problem: refresh portal projection: %w; desired configuration was restored", err)
	}
	fmt.Fprintln(out, "Updated desired configuration atomically. No deployment was performed; run boetticher deploy, then boetticher status.")
	return nil
}

func updateRevision(s model.Site) string {
	revision, err := s.Revision()
	if err != nil {
		return "unavailable"
	}
	return revision
}
