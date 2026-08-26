package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofastercloud/boetticher/internal/portal"
	"github.com/gofastercloud/boetticher/internal/site"
)

func runPortalBuild(args []string, out interface{ Write([]byte) (int, error) }) error {
	fs := flag.NewFlagSet("portal build", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	output := fs.String("output", "", "portal output directory")
	docsDir := fs.String("docs", "docs", "product documentation directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	if *output == "" {
		*output = filepath.Join(*siteDir, "generated", "portal")
	}
	revision, err := s.Revision()
	if err != nil {
		return err
	}
	evidence := loadEvidence(*siteDir, revision)
	if err := portal.Build(s, *output, *docsDir, evidence, loadPhysicalDiscovery(*siteDir, s), time.Now()); err != nil {
		return err
	}
	if err := writeModelProjections(*siteDir, s); err != nil {
		return err
	}
	fmt.Fprintf(out, "Generated passive portal: %s\n", *output)
	return nil
}
