package logging_test

import (
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/logging"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
)

func TestPlanProjectsOptionalCollectorAndManagedSources(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	enabled := true
	config.Modules.Logging = &model.ToggleModuleConfig{Enabled: &enabled}
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := logging.PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Collector != logging.CollectorName || plan.CollectorPort != logging.CollectorPort || plan.CollectorBackendPort != logging.CollectorBackendPort || plan.RemoteJournalPath != logging.RemoteJournalPath || !plan.MTLS {
		t.Fatalf("incomplete logging plan: %#v", plan)
	}
	if len(plan.Sources) != 4 || plan.SourceUnitsOptional == false {
		t.Fatalf("unexpected managed logging sources: %#v", plan.Sources)
	}
	if strings.Contains(logging.CollectorConfiguration(plan), "Requires=") {
		t.Fatal("collector availability became an application startup dependency")
	}
	for _, expected := range []string{"[Remote]", "SplitMode=host", "MaxUse=8G", "KeepFree=1G"} {
		if !strings.Contains(logging.CollectorConfiguration(plan), expected) {
			t.Fatalf("collector configuration omitted %q", expected)
		}
	}
	if strings.Contains(logging.CollectorConfiguration(plan), "[Journal]") || strings.Contains(logging.CollectorConfiguration(plan), "SystemMaxUse=") {
		t.Fatal("collector retention was emitted using journald-only configuration keys")
	}
	if !strings.Contains(logging.CollectorServiceOverride(plan), "LogsDirectory=") || !strings.Contains(logging.CollectorServiceOverride(plan), "ReadWritePaths="+logging.RemoteJournalPath) || !strings.Contains(logging.CollectorServiceOverride(plan), "--listen-http=127.0.0.1:19534") || !strings.Contains(logging.CollectorServiceOverride(plan), logging.RemoteJournalPath) {
		t.Fatal("collector service override does not bind HTTPS journal transport and persistent output")
	}
	if !strings.Contains(logging.CollectorServiceOverride(plan), "ExecStart=/usr/lib/systemd/systemd-journal-remote --listen-http=127.0.0.1:19534 --output="+logging.RemoteJournalPath) {
		t.Fatal("collector service override does not use the loopback HTTP journal backend")
	}
	if strings.Contains(logging.CollectorServiceOverride(plan), "--listen-https") {
		t.Fatal("collector backend still exposes an unrevocable TLS listener")
	}
	if got := logging.CollectorSocketOverride(plan); !strings.Contains(got, "ListenStream=\nListenStream=127.0.0.1:19534") {
		t.Fatalf("collector socket override does not move socket activation to the loopback backend: %q", got)
	}
	if strings.Contains(logging.CollectorConfiguration(plan), "TrustedCertificateFile=") {
		t.Fatal("collector backend configuration still implies direct TLS termination")
	}
	upload := logging.UploadConfiguration(plan, "lab-dns-01")
	if !strings.Contains(upload, "https://logs.lab.home.arpa:19532") {
		t.Fatal("upload configuration does not use the canonical collector URL")
	}
	if strings.Contains(upload, "[Service]") {
		t.Fatal("journal-upload configuration contains a systemd unit section")
	}
}
