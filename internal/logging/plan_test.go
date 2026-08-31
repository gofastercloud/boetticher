package logging

import (
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestPlanProjectsMandatoryCollectorAndManagedSources(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Collector != CollectorName || plan.CollectorPort != 19532 || plan.CollectorBackendPort != 19534 || plan.RemoteJournalPath != RemoteJournalPath || !plan.MTLS {
		t.Fatalf("incomplete logging plan: %#v", plan)
	}
	if len(plan.Sources) != 6 || plan.SourceUnitsOptional == false {
		t.Fatalf("unexpected managed logging sources: %#v", plan.Sources)
	}
	if strings.Contains(CollectorConfiguration(plan), "Requires=") {
		t.Fatal("collector availability became an application startup dependency")
	}
	for _, expected := range []string{"[Remote]", "SplitMode=host", "MaxUse=8G", "KeepFree=1G"} {
		if !strings.Contains(CollectorConfiguration(plan), expected) {
			t.Fatalf("collector configuration omitted %q", expected)
		}
	}
	if strings.Contains(CollectorConfiguration(plan), "[Journal]") || strings.Contains(CollectorConfiguration(plan), "SystemMaxUse=") {
		t.Fatal("collector retention was emitted using journald-only configuration keys")
	}
	if !strings.Contains(CollectorServiceOverride(plan), "LogsDirectory=") || !strings.Contains(CollectorServiceOverride(plan), "ReadWritePaths="+RemoteJournalPath) || !strings.Contains(CollectorServiceOverride(plan), "--listen-http=127.0.0.1:19534") || !strings.Contains(CollectorServiceOverride(plan), RemoteJournalPath) {
		t.Fatal("collector service override does not bind HTTPS journal transport and persistent output")
	}
	if !strings.Contains(CollectorServiceOverride(plan), "ExecStart=/usr/lib/systemd/systemd-journal-remote --listen-http=127.0.0.1:19534 --output="+RemoteJournalPath) {
		t.Fatal("collector service override does not use the loopback HTTP journal backend")
	}
	if strings.Contains(CollectorServiceOverride(plan), "--listen-https") {
		t.Fatal("collector backend still exposes an unrevocable TLS listener")
	}
	if got := CollectorSocketOverride(plan); !strings.Contains(got, "ListenStream=\nListenStream=127.0.0.1:19534") {
		t.Fatalf("collector socket override does not move socket activation to the loopback backend: %q", got)
	}
	if strings.Contains(CollectorConfiguration(plan), "TrustedCertificateFile=") {
		t.Fatal("collector backend configuration still implies direct TLS termination")
	}
	upload := UploadConfiguration(plan, "lab-dns-01")
	if !strings.Contains(upload, "https://logs.lab.home.arpa:19532") {
		t.Fatal("upload configuration does not use the canonical collector URL")
	}
	if strings.Contains(upload, "[Service]") {
		t.Fatal("journal-upload configuration contains a systemd unit section")
	}
}

func TestPlanRejectsMissingMandatoryCollector(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	for index, component := range site.Components {
		if component.Name == CollectorName {
			site.Components = append(site.Components[:index], site.Components[index+1:]...)
			break
		}
	}
	if _, err := PlanFromSite(site); err == nil {
		t.Fatal("missing collector was accepted")
	}
}
