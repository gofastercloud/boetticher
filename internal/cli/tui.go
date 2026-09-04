package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/application"
	"github.com/gofastercloud/boetticher/internal/model"
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
		Commands: applicationCommands(*siteDir, !*offline),
		Executor: applicationExecutor{},
	})
}

type applicationExecutor struct{}

func (applicationExecutor) Execute(ctx context.Context, request application.Request, emit func(application.Event)) (application.Result, error) {
	if err := ctx.Err(); err != nil {
		return application.Result{Operation: request.Operation}, err
	}
	var output, errOutput bytes.Buffer
	if emit == nil {
		emit = func(application.Event) {}
	}
	result := application.Result{Operation: request.Operation}
	var err error
	siteDir := request.SiteDir
	if siteDir == "" {
		siteDir = "."
	}
	switch request.Operation {
	case application.OperationStatus:
		result.Report, err = evaluateStatusRequest(statusRequest{siteDir: siteDir, live: request.Live})
		if result.Report.StatusModelVersion != "" {
			printStatus(&output, result.Report, false)
		}
	case application.OperationPlan:
		err = runPlanRequest(planRequest{siteDir: siteDir, live: request.Live}, &output)
	case application.OperationModuleList:
		err = runModuleListRequest(siteDir, &output)
	case application.OperationDiagnose:
		result.Report, err = evaluateStatusRequest(statusRequest{siteDir: siteDir, live: request.Live, verbose: true})
		if result.Report.StatusModelVersion != "" {
			printStatus(&output, result.Report, true)
		}
	case application.OperationNetworkStatus:
		err = runNetworkTrunkStatusRequest(networkTrunkStatusRequest{siteDir: siteDir, live: request.Live}, &output)
	default:
		err = fmt.Errorf("TUI operation %q is not supported", request.Operation)
	}
	for _, line := range strings.Split(output.String(), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			emit(application.Event{Kind: "output", Message: line})
		}
	}
	if errOutput.Len() > 0 {
		output.WriteString(errOutput.String())
	}
	result.Output = output.String()
	if request.Operation == application.OperationStatus && request.Live && err == nil {
		metrics, metricsErr := readTUIObservability(ctx, request.SiteDir)
		if metricsErr != nil {
			return result, metricsErr
		}
		result.Metrics = &metrics
	}
	return result, err
}

func applicationCommands(siteDir string, live bool) []application.Command {
	return []application.Command{
		{Name: "status", Description: "Read platform status", Request: application.Request{Operation: application.OperationStatus, SiteDir: siteDir, Live: live}},
		{Name: "plan", Description: "Validate the next deployment without changing the lab", Request: application.Request{Operation: application.OperationPlan, SiteDir: siteDir, Live: live, DryRun: true}},
		{Name: "module list", Description: "Inspect enabled first-party modules", Request: application.Request{Operation: application.OperationModuleList, SiteDir: siteDir}},
		{Name: "diagnose", Description: "Explain local and runtime failures", Request: application.Request{Operation: application.OperationDiagnose, SiteDir: siteDir, Live: live}},
		{Name: "network status", Description: "Inspect the physical trunk contract", Request: application.Request{Operation: application.OperationNetworkStatus, SiteDir: siteDir, Live: live}},
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
	forward, err := proxmoxBastionSSHRunner(s, siteDir).StartLocalForward(ctx, s.BootstrapAddress, "lab-jump", "10.10.10.20", 443)
	if err != nil {
		return application.Metrics{}, fmt.Errorf("open Pulse API tunnel: %w", err)
	}
	defer forward.Close()
	client, err := pulse.NewReadClient(pulse.ClientConfig{
		BaseURL: "https://" + forward.Address(), APIToken: token,
		CAPEM:      authority.RootCertPEM,
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
