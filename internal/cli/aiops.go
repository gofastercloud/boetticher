package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gofastercloud/boetticher/internal/aiops"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/site"
)

func runAIOps(args []string, out interface{ Write([]byte) (int, error) }) error {
	if len(args) == 0 || args[0] != "status" {
		return errors.New("usage: boetticher aiops status [--site DIR] [--live] [--json]")
	}
	fs := flag.NewFlagSet("aiops status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	live := fs.Bool("live", false, "read bounded live adapter status")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	if !modules.IsEnabled(s, "aiops") {
		return errors.New("aiops module is disabled")
	}
	if !*live {
		value := map[string]any{"enabled": true, "model_alias": s.ModuleConfig["aiops"].ModelAlias, "status": "NOT TESTED", "detail": "use --live for bounded appliance status"}
		if *asJSON {
			return json.NewEncoder(out).Encode(value)
		}
		fmt.Fprintf(out, "AIOps enabled\nModel alias %s\nLive status NOT TESTED (use --live)\n", s.ModuleConfig["aiops"].ModelAlias)
		return nil
	}
	component, ok := findManagedEndpoint(s, "lab-aiops-01")
	if !ok {
		return errors.New("aiops appliance is absent from the model")
	}
	runner := proxmox.SSHRunner{ConfigFile: filepath.Join(*siteDir, "generated", "ssh", "boetticher.conf"), HostAlias: component.Name, StrictHostKey: "accept-new"}
	data, err := runner.RunArgs(context.Background(), component.Address, model.DefaultAdminSSHUser, []string{"/usr/local/libexec/boetticher-aiops", "status"})
	if err != nil {
		return fmt.Errorf("read AIOps status: %w", err)
	}
	var status aiops.Status
	if err := json.Unmarshal(data, &status); err != nil {
		return fmt.Errorf("decode AIOps status: %w", err)
	}
	if *asJSON {
		_, err = out.Write(data)
		return err
	}
	fmt.Fprintf(out, "AIOps live status\nInvestigations 24h %d\nTokens 24h input=%d output=%d\nPending notes %d failed=%d\n", status.Investigations24h, status.InputTokens24h, status.OutputTokens24h, status.PendingNoteWrites, status.FailedNoteWrites)
	for _, state := range []aiops.State{aiops.StateQueued, aiops.StateRunning, aiops.StateCompleted, aiops.StateInconclusive, aiops.StateDeferred, aiops.StateFailed, aiops.StateResolved} {
		fmt.Fprintf(out, "%-14s %d\n", state, status.States[state])
	}
	return nil
}
