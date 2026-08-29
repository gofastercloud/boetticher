package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/pathguard"
	"github.com/gofastercloud/boetticher/internal/site"
	statusmodel "github.com/gofastercloud/boetticher/internal/status"
)

func runStatus(args []string, out interface{ Write([]byte) (int, error) }) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	live := fs.Bool("live", false, "perform bounded read-only managed-gateway inspection")
	verbose := fs.Bool("verbose", false, "include reasons and safe next actions")
	jsonOutput := fs.Bool("json", false, "write the versioned semantic status model")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return fmt.Errorf("Problem: load site: %w", err)
	}
	revision, err := s.Revision()
	if err != nil {
		return fmt.Errorf("Problem: calculate model revision: %w", err)
	}
	report := loadStatusReport(*siteDir, revision)
	if len(report.Checks) == 0 {
		report = desiredStatusReport(s, revision)
	}

	var liveErr error
	if *live {
		if s.Gateway.Mode == model.GatewayModeExternal {
			check := statusmodel.Check{
				Component:  "managed gateway DHCP/DDNS",
				State:      statusmodel.ActionRequired,
				Evidence:   statusmodel.NOTTESTED,
				Tier:       statusmodel.TierDeployed,
				ObservedAt: time.Now().UTC().Format(time.RFC3339),
				Reason:     "DHCP is managed by the external firewall and is unavailable to Boetticher",
				NextAction: "Inspect DHCP and DDNS using the external firewall's supported interface",
			}
			report = replaceStatusCheck(report, check)
			liveErr = errors.New("ACTION REQUIRED: live managed-gateway inspection is unavailable in external-firewall mode")
		} else {
			attemptedAt := time.Now().UTC().Format(time.RFC3339)
			_, observedAt, inspectErr := inspectManagedDHCP(*siteDir, s)
			if observedAt == "" {
				observedAt = attemptedAt
			}
			check := statusmodel.Check{
				Component:  "managed gateway DHCP/DDNS",
				State:      statusmodel.Healthy,
				Evidence:   statusmodel.PASS,
				Tier:       statusmodel.TierDeployed,
				ObservedAt: observedAt,
				Reason:     "kea-dhcp4-server and kea-dhcp-ddns-server are active",
				NextAction: "No action required",
			}
			if inspectErr != nil {
				check.State = statusmodel.Failed
				check.Evidence = statusmodel.FAIL
				check.Reason = inspectErr.Error()
				check.NextAction = "Restore both Kea services and repeat status --live"
				liveErr = inspectErr
			}
			report = replaceStatusCheck(report, check)
		}
		report.ObservedAt = time.Now().UTC().Format(time.RFC3339)
		report.OverallState = statusmodel.Overall(report.Checks)
	}

	if *jsonOutput {
		if err := writeCLIJSON(out, report); err != nil {
			return err
		}
	} else {
		printStatus(out, report, *verbose)
	}
	if liveErr != nil {
		return liveErr
	}
	if report.OverallState == statusmodel.Failed || report.OverallState == statusmodel.ActionRequired || report.OverallState == statusmodel.Degraded {
		return fmt.Errorf("status is %s; review the safe next action", report.OverallState)
	}
	return nil
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
	return report
}

func desiredStatusReport(s model.Site, revision string) statusmodel.Report {
	now := time.Now().UTC().Format(time.RFC3339)
	checks := []statusmodel.LegacyCheck{{Name: "desired platform model", Status: "PASS", Detail: "typed v3 desired state composed locally"}}
	for _, module := range s.Modules {
		if module.Enabled {
			checks = append(checks, statusmodel.LegacyCheck{Name: module.Name, Status: "NOT TESTED", Detail: "module runtime evidence requires deployment or an explicit live check"})
		} else {
			checks = append(checks, statusmodel.LegacyCheck{Name: module.Name, Status: "NOT TESTED", Detail: "optional module is intentionally disabled"})
		}
	}
	report := statusmodel.FromLegacy(revision, now, checks)
	for _, module := range s.Modules {
		if !module.Enabled {
			// The desired-state check is the first entry; module order is stable
			// in the composed model and the matching name avoids an index contract.
			for checkIndex := range report.Checks {
				if report.Checks[checkIndex].Component == module.Name {
					report.Checks[checkIndex].State = statusmodel.Disabled
				}
			}
		}
	}
	report.OverallState = statusmodel.Overall(report.Checks)
	return report
}

func replaceStatusCheck(report statusmodel.Report, replacement statusmodel.Check) statusmodel.Report {
	for index := range report.Checks {
		if report.Checks[index].Component == replacement.Component {
			report.Checks[index] = replacement
			return report
		}
	}
	report.Checks = append(report.Checks, replacement)
	return report
}

func printStatus(out interface{ Write([]byte) (int, error) }, report statusmodel.Report, verbose bool) {
	fmt.Fprintf(out, "Platform %s\n", report.OverallState)
	fmt.Fprintf(out, "Observed: %s\n", report.ObservedAt)
	for _, check := range report.Checks {
		fmt.Fprintf(out, "%-32s %-16s %s (%s)\n", check.Component, check.State, check.Evidence, check.Tier)
		if verbose {
			fmt.Fprintf(out, "  Reason: %s\n  Next:   %s\n", check.Reason, check.NextAction)
		}
	}
	if strings.TrimSpace(string(report.OverallState)) == "" {
		fmt.Fprintln(out, "Platform ACTION REQUIRED")
	}
}
