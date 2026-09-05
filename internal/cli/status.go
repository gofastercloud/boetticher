package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/pathguard"
	"github.com/gofastercloud/boetticher/internal/site"
	"github.com/gofastercloud/boetticher/internal/sshconfig"
	statusmodel "github.com/gofastercloud/boetticher/internal/status"
)

func runStatus(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	sshPath := fs.String("ssh-config", sshconfig.DefaultPath(), "generated SSH configuration to inspect")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	sshJourney := fs.Bool("ssh-journey", false, "run an authenticated internal SSH journey through the bastion")
	live := fs.Bool("live", false, "inspect the managed gateway over the generated SSH path")
	details := fs.Bool("details", false, "include reasons and safe next actions")
	jsonOutput := fs.Bool("json", false, "write the versioned semantic status model")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return runStatusRequest(statusRequest{
		siteDir: *siteDir, sshPath: *sshPath, ageIdentity: *ageIdentity, sshJourney: *sshJourney,
		live: *live, verbose: *details, json: *jsonOutput,
	}, out)
}

type statusRequest struct {
	siteDir     string
	sshPath     string
	ageIdentity string
	sshJourney  bool
	live        bool
	verbose     bool
	json        bool
}

func runStatusRequest(request statusRequest, out io.Writer) error {
	report, err := evaluateStatusRequest(request)
	if report.StatusModelVersion != "" {
		if request.json {
			if err := writeCLIJSON(out, report); err != nil {
				return err
			}
		} else {
			printStatus(out, report, request.verbose)
		}
	}
	return err
}

func evaluateStatusRequest(request statusRequest) (statusmodel.Report, error) {
	siteDir, sshPath := request.siteDir, request.sshPath
	if siteDir == "" {
		siteDir = "."
	}
	if sshPath == "" {
		sshPath = sshconfig.DefaultPath()
	}
	s, err := site.Load(siteDir)
	if err != nil {
		return statusmodel.Report{}, fmt.Errorf("Problem: load site: %w", err)
	}
	revision, err := s.Revision()
	if err != nil {
		return statusmodel.Report{}, fmt.Errorf("Problem: calculate model revision: %w", err)
	}
	results, observedAt, err := collectHealthResults(healthOptions{
		siteDir: siteDir, sshPath: sshPath, ageIdentity: request.ageIdentity, sshJourney: request.sshJourney, live: request.live,
	}, s)
	if err != nil {
		return statusmodel.Report{}, fmt.Errorf("collect health results: %w", err)
	}
	report := healthStatusReport(revision, observedAt, results)
	if report.OverallState == statusmodel.Failed || report.OverallState == statusmodel.ActionRequired || report.OverallState == statusmodel.Degraded {
		return report, fmt.Errorf("status is %s; review the safe next action", report.OverallState)
	}
	return report, nil
}

func loadStatusReport(dir, revision string) statusmodel.Report {
	data, err := pathguard.ReadFile(filepath.Join(dir, "generated", "status.json"))
	if err != nil {
		return statusmodel.Report{}
	}
	var report statusmodel.Report
	if json.Unmarshal(data, &report) != nil || report.StatusModelVersion != statusmodel.ModelVersion || report.ModelRevision != revision {
		return statusmodel.Report{}
	}
	return filterHealthStatusReport(report)
}

func filterHealthStatusReport(report statusmodel.Report) statusmodel.Report {
	checks := make([]statusmodel.Check, 0, len(report.Checks))
	for index := range report.Checks {
		check := report.Checks[index]
		definition, ok := checkDefinitionByID(check.ID)
		if !ok && check.ID == "" {
			definition, ok = checkDefinitionByLabel(check.Component)
			if ok {
				check.ID = definition.ID
			}
		}
		if ok && definition.HealthVisible {
			check.Component = definition.Label
			check.Tier = definition.EvidenceTier
			checks = append(checks, check)
		}
	}
	if len(checks) == 0 {
		return statusmodel.Report{}
	}
	report.Checks = checks
	report.OverallState = statusmodel.Overall(checks)
	return report
}

func desiredStatusReport(s model.Site, revision string) statusmodel.Report {
	now := time.Now().UTC().Format(time.RFC3339)
	checks := []statusmodel.LegacyCheck{{ID: checkDesiredPlatformModel, Name: "desired platform model", Status: "PASS", Detail: "typed v3 desired state composed locally"}}
	report := statusmodel.FromLegacy(revision, now, checks)
	report.OverallState = statusmodel.Overall(report.Checks)
	return report
}

func printStatus(out io.Writer, report statusmodel.Report, verbose bool) {
	fmt.Fprintf(out, "Platform %s\n", report.OverallState)
	fmt.Fprintf(out, "Observed: %s\n", report.ObservedAt)
	for _, check := range report.Checks {
		fmt.Fprintf(out, "%-32s %-16s %s (%s)\n", check.Component, check.State, operatorEvidenceLabel(check.Evidence), check.Tier)
		if verbose {
			fmt.Fprintf(out, "  Reason: %s\n  Next:   %s\n", check.Reason, check.NextAction)
		}
	}
	if strings.TrimSpace(string(report.OverallState)) == "" {
		fmt.Fprintln(out, "Platform ACTION REQUIRED")
	}
}

func operatorEvidenceLabel(evidence statusmodel.EvidenceStatus) statusmodel.EvidenceStatus {
	if evidence == statusmodel.PASS {
		return statusmodel.PASS
	}
	return statusmodel.FAIL
}
