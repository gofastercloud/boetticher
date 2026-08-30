package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/pki"
	"github.com/gofastercloud/boetticher/internal/pulse"
	"github.com/gofastercloud/boetticher/internal/site"
	"github.com/gofastercloud/boetticher/internal/tui"
)

func runTUI(args []string, input io.Reader, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("tui", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	offline := fs.Bool("offline", false, "skip live status refresh")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: boetticher tui [--site DIR] [--offline]")
	}
	return tui.Run(tui.Options{
		SiteDir:  *siteDir,
		Offline:  *offline,
		Commands: CommandUsages(),
		Runner: func(commandArgs []string, commandInput io.Reader, commandOut, commandErrOut io.Writer) error {
			return run(commandArgs, commandInput, commandOut, commandErrOut)
		},
		Observability: func(ctx context.Context) (tui.Observability, error) {
			return readTUIObservability(ctx, *siteDir)
		},
	})
}

func readTUIObservability(ctx context.Context, siteDir string) (tui.Observability, error) {
	s, err := site.Load(siteDir)
	if err != nil {
		return tui.Observability{}, fmt.Errorf("load site for Pulse observability: %w", err)
	}
	plan, err := pulse.PlanFromSite(s)
	if err != nil {
		return tui.Observability{}, fmt.Errorf("plan Pulse observability: %w", err)
	}
	if len(plan.Components) == 0 || s.BootstrapAddress == "" {
		return tui.Observability{}, errors.New("Pulse observability is unavailable before deployment")
	}
	authority, err := site.LoadAuthority(siteDir, s, model.DefaultAgeIdentity)
	if err != nil {
		return tui.Observability{}, fmt.Errorf("load Pulse trust: %w", err)
	}
	token, err := site.LoadPlatformSecret(siteDir, s, model.DefaultAgeIdentity, "pulse_api_token")
	if err != nil {
		return tui.Observability{}, fmt.Errorf("load Pulse read credential: %w", err)
	}
	certificate, err := pki.IssueClient(authority, "boetticher-tui", s.Network.Domain, time.Now().UTC())
	if err != nil {
		return tui.Observability{}, fmt.Errorf("issue Pulse client certificate: %w", err)
	}
	forward, err := proxmoxBastionSSHRunner(s, siteDir).StartLocalForward(ctx, s.BootstrapAddress, "lab-jump", "10.10.10.20", 443)
	if err != nil {
		return tui.Observability{}, fmt.Errorf("open Pulse API tunnel: %w", err)
	}
	defer forward.Close()
	client, err := pulse.NewReadClient(pulse.ClientConfig{
		BaseURL: "https://" + forward.Address(), APIToken: token,
		CAPEM: authority.IssuingCertPEM, ClientCertPEM: certificate.CertPEM, ClientKeyPEM: certificate.KeyPEM,
		ServerName: "monitor." + s.Network.Domain,
	})
	if err != nil {
		return tui.Observability{}, err
	}
	health, err := client.Health(ctx)
	if err != nil {
		return tui.Observability{}, err
	}
	summary, err := client.StateSummary(ctx)
	if err != nil {
		return tui.Observability{}, err
	}
	resources, err := client.Resources(ctx)
	if err != nil {
		return tui.Observability{}, err
	}
	return tui.Observability{
		Health: health.Status, ActiveAlerts: summary.ActiveAlerts, Nodes: summary.Nodes,
		VMs: summary.VMs, Containers: summary.Containers, Resources: len(resources.Data),
		LastUpdate: summary.LastUpdate.UTC().Format(time.RFC3339),
	}, nil
}
