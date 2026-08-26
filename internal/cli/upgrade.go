package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/site"
)

func runIntegrationGate(command string, args []string, out interface{ Write([]byte) (int, error) }) error {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	recoveryConfirmed := fs.Bool("recovery-confirmed", false, "confirm an independent Age recovery copy exists")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	if command == "bootstrap" {
		identityPath := model.ExpandUserPath(*ageIdentity)
		if _, err := os.Stat(identityPath); err != nil {
			return fmt.Errorf("HOLD: Age identity is not available at %s", identityPath)
		}
		if !*recoveryConfirmed {
			return fmt.Errorf("HOLD: destructive bootstrap requires --recovery-confirmed after an independent Age recovery copy is secured")
		}
	}
	if command == "upgrade" {
		fmt.Fprintln(out, "HOLD: compatibility qualification and migration are required before upgrade")
	} else {
		fmt.Fprintf(out, "HOLD: %s requires the authenticated Proxmox integration path; no mutation was performed\n", command)
	}
	_ = s
	return fmt.Errorf("%s integration gate is not yet satisfied", command)
}
