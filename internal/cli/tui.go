package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/application"
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
		Commands: applicationCommands(*siteDir),
		Executor: applicationExecutor{},
	})
}

type applicationExecutor struct{}

func (applicationExecutor) Execute(ctx context.Context, request application.Request, emit func(application.Event)) (application.Result, error) {
	if err := ctx.Err(); err != nil {
		return application.Result{Operation: request.Operation}, err
	}
	args := applicationArgs(request)
	var output, errOutput bytes.Buffer
	if emit == nil {
		emit = func(application.Event) {}
	}
	err := run(args, os.Stdin, &output, &errOutput)
	for _, line := range strings.Split(output.String(), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			emit(application.Event{Kind: "output", Message: line})
		}
	}
	if errOutput.Len() > 0 {
		output.WriteString(errOutput.String())
	}
	result := application.Result{Operation: request.Operation, Output: output.String()}
	if request.Operation == application.OperationStatus && output.Len() > 0 {
		_ = json.Unmarshal(output.Bytes(), &result.Report)
	}
	if request.Operation == application.OperationStatus && request.Live && err == nil {
		metrics, metricsErr := readTUIObservability(ctx, request.SiteDir)
		if metricsErr != nil {
			return result, metricsErr
		}
		result.Metrics = &metrics
	}
	return result, err
}

func applicationArgs(request application.Request) []string {
	var args []string
	switch request.Operation {
	case application.OperationStatus:
		args = []string{"status"}
		if request.Live {
			args = append(args, "--live")
		}
		args = append(args, "--json")
	case application.OperationPlan:
		args = []string{"deploy", "--dry-run"}
	case application.OperationModuleList:
		args = []string{"module", "list"}
	case application.OperationDiagnose:
		args = []string{"doctor"}
	case application.OperationNetworkStatus:
		args = []string{"network", "trunk", "status"}
	default:
		args = []string{"status"}
	}
	if request.SiteDir != "" {
		args = append(args, "--site", request.SiteDir)
	}
	return args
}

func applicationCommands(siteDir string) []application.Command {
	return []application.Command{
		{Name: "status", Description: "Read platform status", Request: application.Request{Operation: application.OperationStatus, SiteDir: siteDir, Live: true}},
		{Name: "plan", Description: "Validate the next deployment without changing the lab", Request: application.Request{Operation: application.OperationPlan, SiteDir: siteDir, DryRun: true}},
		{Name: "module list", Description: "Inspect enabled first-party modules", Request: application.Request{Operation: application.OperationModuleList, SiteDir: siteDir}},
		{Name: "diagnose", Description: "Explain local and runtime failures", Request: application.Request{Operation: application.OperationDiagnose, SiteDir: siteDir}},
		{Name: "network status", Description: "Inspect the physical trunk contract", Request: application.Request{Operation: application.OperationNetworkStatus, SiteDir: siteDir}},
	}
}

func readTUIObservability(ctx context.Context, siteDir string) (application.Metrics, error) {
	s, err := site.Load(siteDir)
	if err != nil {
		return application.Metrics{}, fmt.Errorf("load site for Pulse observability: %w", err)
	}
	plan, err := pulse.PlanFromSite(s)
	if err != nil {
		return application.Metrics{}, fmt.Errorf("plan Pulse observability: %w", err)
	}
	if len(plan.Components) == 0 || s.BootstrapAddress == "" {
		return application.Metrics{}, errors.New("Pulse observability is unavailable before deployment")
	}
	authority, err := site.LoadAuthority(siteDir, s, model.DefaultAgeIdentity)
	if err != nil {
		return application.Metrics{}, fmt.Errorf("load Pulse trust: %w", err)
	}
	token, err := site.LoadPlatformSecret(siteDir, s, model.DefaultAgeIdentity, "pulse_api_token")
	if err != nil {
		return application.Metrics{}, fmt.Errorf("load Pulse read credential: %w", err)
	}
	certificate, err := pki.IssueClient(authority, "boetticher-tui", s.Network.Domain, time.Now().UTC())
	if err != nil {
		return application.Metrics{}, fmt.Errorf("issue Pulse client certificate: %w", err)
	}
	forward, err := proxmoxBastionSSHRunner(s, siteDir).StartLocalForward(ctx, s.BootstrapAddress, "lab-jump", "10.10.10.20", 443)
	if err != nil {
		return application.Metrics{}, fmt.Errorf("open Pulse API tunnel: %w", err)
	}
	defer forward.Close()
	client, err := pulse.NewReadClient(pulse.ClientConfig{
		BaseURL: "https://" + forward.Address(), APIToken: token,
		CAPEM: authority.IssuingCertPEM, ClientCertPEM: certificate.CertPEM, ClientKeyPEM: certificate.KeyPEM,
		ServerName: "monitor." + s.Network.Domain,
	})
	if err != nil {
		return application.Metrics{}, err
	}
	health, err := client.Health(ctx)
	if err != nil {
		return application.Metrics{}, err
	}
	summary, err := client.StateSummary(ctx)
	if err != nil {
		return application.Metrics{}, err
	}
	resources, err := client.Resources(ctx)
	if err != nil {
		return application.Metrics{}, err
	}
	return application.Metrics{
		Health: health.Status, ActiveAlerts: summary.ActiveAlerts, Nodes: summary.Nodes,
		VMs: summary.VMs, Containers: summary.Containers, Resources: len(resources.Data),
		LastUpdate: summary.LastUpdate.UTC().Format(time.RFC3339),
	}, nil
}
