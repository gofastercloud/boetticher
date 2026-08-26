package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/gofastercloud/boetticher/internal/site"
)

func runOPNsense(args []string, out interface{ Write([]byte) (int, error) }) error {
	if len(args) < 2 || args[0] != "credentials" || args[1] != "import" {
		return errors.New("usage: boetticher opnsense credentials import [--site DIR] < credentials.json")
	}
	fs := flag.NewFlagSet("opnsense credentials import", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 64<<10))
	if err != nil {
		return fmt.Errorf("read OPNsense credential input: %w", err)
	}
	var credentials site.OPNsenseCredentials
	if err := json.Unmarshal(data, &credentials); err != nil {
		return errors.New("OPNsense credential input must be a JSON object with api_key and api_secret")
	}
	if err := site.StoreOPNsenseCredentials(*siteDir, s, credentials); err != nil {
		return err
	}
	if s.BootstrapAddress != "" {
		if err := rebuildPortal(*siteDir, s); err != nil {
			return err
		}
	}
	fmt.Fprintln(out, "Stored OPNsense API credentials in encrypted SOPS state")
	return nil
}
