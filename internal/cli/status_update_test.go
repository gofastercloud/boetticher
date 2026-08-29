package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	statusmodel "github.com/gofastercloud/boetticher/internal/status"
)

func writeTestSiteConfig(t *testing.T, dir string, config model.SiteConfig) []byte {
	t.Helper()
	data, err := model.RenderSiteConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "site.yml"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestStatusJSONUsesSemanticModelAndDeterministicExit(t *testing.T) {
	dir := t.TempDir()
	writeTestSiteConfig(t, dir, model.ConfigFromSite(model.NewSite("status-test", "age1status", model.GatewayModeManaged)))

	var output bytes.Buffer
	err := runStatus([]string{"--site", dir, "--json"}, &output)
	if err == nil || !strings.Contains(err.Error(), "ACTION REQUIRED") {
		t.Fatalf("status without deployment evidence returned %v", err)
	}
	var report statusmodel.Report
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("status JSON is not the semantic model: %v\n%s", err, output.String())
	}
	if report.StatusModelVersion != statusmodel.ModelVersion || report.OverallState != statusmodel.ActionRequired {
		t.Fatalf("unexpected status report: %#v", report)
	}
	for _, check := range report.Checks {
		if check.Component == "monitoring" && check.Evidence != statusmodel.NOTTESTED {
			t.Fatalf("enabled module was reported as live evidence: %#v", check)
		}
	}
}

func TestUpdateDryRunDoesNotMutateAndConfirmRefreshesDesiredState(t *testing.T) {
	dir := t.TempDir()
	config := model.ConfigFromSite(model.NewSite("update-test", "age1update", model.GatewayModeManaged))
	config.PlatformVersion = "0.3.34"
	original := writeTestSiteConfig(t, dir, config)

	var dryRun bytes.Buffer
	if err := runUpdate([]string{"--site", dir, "--dry-run"}, &dryRun); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dryRun.String(), "0.3.34 -> 0.4.0") || !strings.Contains(dryRun.String(), "deploy has not been called") {
		t.Fatalf("dry-run did not explain the guarded update: %s", dryRun.String())
	}
	if got, err := os.ReadFile(filepath.Join(dir, "site.yml")); err != nil || !bytes.Equal(got, original) {
		t.Fatalf("dry-run changed authoritative configuration: %v", err)
	}

	var confirmed bytes.Buffer
	if err := runUpdate([]string{"--site", dir, "--confirm"}, &confirmed); err != nil {
		t.Fatal(err)
	}
	updated, err := os.ReadFile(filepath.Join(dir, "site.yml"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := model.ParseSiteConfig(updated)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.PlatformVersion != model.PlatformVersion {
		t.Fatalf("confirmed update did not persist platform version: %q", parsed.PlatformVersion)
	}
	status, err := os.ReadFile(filepath.Join(dir, "generated", "status.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(status, []byte(statusmodel.ModelVersion)) {
		t.Fatalf("confirmed update did not refresh semantic status projection: %s", status)
	}
	if !strings.Contains(confirmed.String(), "No deployment was performed") {
		t.Fatalf("confirmed update did not preserve deploy boundary: %s", confirmed.String())
	}
}

func TestUpdateRestoresDesiredStateWhenProjectionRefreshFails(t *testing.T) {
	dir := t.TempDir()
	config := model.ConfigFromSite(model.NewSite("update-failure", "age1failure", model.GatewayModeManaged))
	config.PlatformVersion = "0.3.34"
	original := writeTestSiteConfig(t, dir, config)
	if err := os.MkdirAll(filepath.Join(dir, "generated"), 0700); err != nil {
		t.Fatal(err)
	}
	external := t.TempDir()
	if err := os.Symlink(external, filepath.Join(dir, "generated", "modules")); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runUpdate([]string{"--site", dir, "--confirm"}, &output); err == nil || !strings.Contains(err.Error(), "desired configuration was restored") {
		t.Fatalf("projection failure was not reported as a guarded rollback: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "site.yml")); err != nil || !bytes.Equal(got, original) {
		t.Fatalf("projection failure changed authoritative configuration: %v", err)
	}
}

func TestProjectionRefreshPreservesSameRevisionStatusEvidence(t *testing.T) {
	dir := t.TempDir()
	s := model.NewDefaultSite("status-preserve", "age1statuspreserve")
	revision, err := s.Revision()
	if err != nil {
		t.Fatal(err)
	}
	existing := statusmodel.Report{
		StatusModelVersion: statusmodel.ModelVersion,
		ModelRevision:      revision,
		ObservedAt:         "2026-08-29T12:00:00Z",
		OverallState:       statusmodel.Failed,
		Checks: []statusmodel.Check{{
			Component:  "managed gateway DHCP/DDNS",
			State:      statusmodel.Failed,
			Evidence:   statusmodel.FAIL,
			Tier:       statusmodel.TierJourney,
			ObservedAt: "2026-08-29T11:59:00Z",
			Reason:     "gateway evidence was unavailable",
			NextAction: "Restore the gateway and repeat the check",
		}},
	}
	if err := writeProjection(filepath.Join(dir, "generated", "status.json"), existing); err != nil {
		t.Fatal(err)
	}
	if err := writeModelProjections(dir, s); err != nil {
		t.Fatal(err)
	}
	got := loadStatusReport(dir, revision)
	if len(got.Checks) != 1 || got.Checks[0].Evidence != statusmodel.FAIL || got.Checks[0].Tier != statusmodel.TierJourney {
		t.Fatalf("projection refresh replaced same-revision live evidence: %#v", got)
	}
	if got.Checks[0].ObservedAt != existing.Checks[0].ObservedAt || got.ObservedAt != existing.ObservedAt {
		t.Fatalf("projection refresh changed evidence timestamps: %#v", got)
	}
}

func TestPreflightRecordRequiresLive(t *testing.T) {
	var output bytes.Buffer
	if err := runPreflight([]string{"--record"}, &output); err == nil || !strings.Contains(err.Error(), "requires --live") {
		t.Fatalf("preflight accepted persistence without live inspection: %v", err)
	}
}
