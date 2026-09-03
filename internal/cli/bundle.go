package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/gofastercloud/boetticher/internal/artifacts"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/pathguard"
)

func runBundle(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher bundle inspect|import PATH [--site DIR] [--json]")
	}
	switch args[0] {
	case "inspect":
		return runBundleInspect(args[1:], out)
	case "import":
		return runBundleImport(args[1:], out)
	default:
		return fmt.Errorf("unknown bundle command %q", args[0])
	}
}

func runBundleInspect(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("bundle inspect", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOutput := fs.Bool("json", false, "emit the manifest as JSON")
	path := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		path, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if path == "" && fs.NArg() == 1 {
		path = fs.Arg(0)
	}
	if path == "" || fs.NArg() != 0 {
		return errors.New("usage: boetticher bundle inspect PATH [--json]")
	}
	manifest, err := artifacts.InspectReleaseBundle(path)
	if err != nil {
		return err
	}
	if *jsonOutput {
		data, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(data))
		return err
	}
	fmt.Fprintf(out, "Release bundle: PASS\n  Release: %s\n  Source: %s\n  Workflow: %s\n  Schema: %d\n  ABI: %s\n  Architecture: %s\n  Artifacts: %d\n", manifest.ReleaseVersion, manifest.SourceCommit, manifest.BuildWorkflow, manifest.SchemaVersion, manifest.ArtifactABIVersion, manifest.Architecture, len(manifest.Artifacts))
	return nil
}

func runBundleImport(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("bundle import", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	jsonOutput := fs.Bool("json", false, "emit the imported manifest as JSON")
	path := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		path, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if path == "" && fs.NArg() == 1 {
		path = fs.Arg(0)
	}
	if path == "" || fs.NArg() != 0 {
		return errors.New("usage: boetticher bundle import PATH [--site DIR] [--json]")
	}
	keys, err := artifacts.TrustedReleaseKeys()
	if err != nil {
		return fmt.Errorf("load trusted release keys: %w", err)
	}
	if len(keys) == 0 {
		return errors.New("no trusted release keys are embedded in this controller; install a release-built controller or configure its approved key ring")
	}
	if err := pathguard.ValidateNoSymlinkComponents(filepath.Join(*siteDir, "generated")); err != nil {
		return err
	}
	staged := filepath.Join(*siteDir, "generated", ".release-import")
	if err := pathguard.RemoveAll(staged); err != nil {
		return fmt.Errorf("remove stale release staging tree: %w", err)
	}
	defer pathguard.RemoveAll(staged)
	manifest, err := artifacts.ImportReleaseBundle(path, staged, keys, model.ReleaseVersion, model.APIVersion, model.ConfigSchemaVersion)
	if err != nil {
		return err
	}
	active := filepath.Join(*siteDir, "generated", "release")
	if err := artifacts.ActivateImportedRelease(staged, active); err != nil {
		return fmt.Errorf("activate imported release: %w", err)
	}
	if *jsonOutput {
		data, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(data))
		return err
	}
	fmt.Fprintf(out, "Release bundle: PASS imported %s with %d artifact(s)\n", manifest.ReleaseVersion, len(manifest.Artifacts))
	return nil
}
