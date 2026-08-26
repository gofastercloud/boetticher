package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	"github.com/gofastercloud/boetticher/internal/site"
)

func runConfig(args []string, out interface{ Write([]byte) (int, error) }) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher config validate|show|schema")
	}
	fs := flag.NewFlagSet("config "+args[0], flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "validate":
		config, err := site.LoadConfig(*siteDir)
		if err != nil {
			return err
		}
		resolved, _, err := modules.Compose(config)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Configuration: PASS model %s\n", mustRevision(resolved))
		return nil
	case "show":
		config, err := site.LoadConfig(*siteDir)
		if err != nil {
			return err
		}
		resolved, _, err := modules.Compose(config)
		if err != nil {
			return err
		}
		data, err := model.RenderSiteConfig(model.ConfigFromSite(resolved))
		if err != nil {
			return err
		}
		_, err = out.Write(data)
		return err
	case "schema":
		path := filepath.Join(*siteDir, "schemas", "site.schema.json")
		if _, err := os.Stat(path); err == nil {
			fmt.Fprintln(out, path)
			return nil
		}
		fmt.Fprintln(out, filepath.Join("schemas", "site.schema.json"))
		return nil
	default:
		return fmt.Errorf("unknown config command %q", args[0])
	}
}
