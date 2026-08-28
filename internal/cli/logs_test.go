package cli

import (
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestLogsRejectsMultipleHostsBeforeLoadingSite(t *testing.T) {
	err := runLogs([]string{"lab-dns-01", "lab-dns-02"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "at most one managed HOST") {
		t.Fatalf("multiple log hosts were not rejected: %v", err)
	}
}

func TestLogsAcceptsHostBeforeFlags(t *testing.T) {
	args := []string{"lab-dns-01", "--site", "/tmp/site", "--unit", "blocky", "--limit", "20"}
	if got := normalizeLogsArgs(args); !reflect.DeepEqual(got, []string{"--site", "/tmp/site", "--unit", "blocky", "--limit", "20", "lab-dns-01"}) {
		t.Fatalf("logs arguments reordered to %#v", got)
	}
}

func TestNormalizeJournalUnitAcceptsBoundedServiceShorthand(t *testing.T) {
	if got, err := normalizeJournalUnit("blocky"); err != nil || got != "blocky.service" {
		t.Fatalf("bare service unit normalized to %q, %v", got, err)
	}
	if got, err := normalizeJournalUnit("blocky.service"); err != nil || got != "blocky.service" {
		t.Fatalf("qualified service unit changed to %q, %v", got, err)
	}
}

func TestNormalizeJournalUnitRejectsShellAndPathSyntax(t *testing.T) {
	for _, value := range []string{"blocky;id", "../../shadow", "", ".service", "foo..service"} {
		if _, err := normalizeJournalUnit(value); err == nil {
			t.Fatalf("unsafe unit %q was accepted", value)
		}
	}
}

func TestJournalQueryUsesCollectorRemoteStoreAndStableHostMatch(t *testing.T) {
	component := model.Component{Name: "lab-dns-01", Hostname: "lab-dns-01", Address: "10.10.10.10"}
	collector := model.Component{Name: "lab-log-01", Hostname: "lab-log-01", Address: "10.10.10.40"}
	got, source := journalQuery(component, collector, 25, "blocky.service", "2026-08-27T00:00:00Z", "warning")
	want := []string{
		"journalctl", "--no-pager", "--output=short-iso", "--lines=25",
		"--directory=/var/log/journal/remote", "_HOSTNAME=lab-dns-01",
		"_SYSTEMD_UNIT=blocky.service", "--since=2026-08-27T00:00:00Z", "-p", "warning",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("remote journal query = %#v, want %#v", got, want)
	}
	if source != "collected journal for lab-dns-01" {
		t.Fatalf("remote journal source = %q", source)
	}
	if strings.Contains(strings.Join(got, " "), "lab-dns-01/") {
		t.Fatal("remote journal query derived a user-controlled journal path")
	}
}

func TestJournalQueryUsesNativeProxmoxHostnameForLogicalHost(t *testing.T) {
	component := model.Component{Name: model.LogicalProxmoxIdentity, Hostname: model.LogicalProxmoxIdentity, Address: "192.168.4.5"}
	collector := model.Component{Name: "lab-log-01", Hostname: "lab-log-01", Address: "10.10.10.40"}
	got, source := journalQuery(component, collector, 25, "", "", "")
	want := []string{
		"journalctl", "--no-pager", "--output=short-iso", "--lines=25",
		"--directory=/var/log/journal/remote", "_HOSTNAME=proxmox",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Proxmox remote journal query = %#v, want %#v", got, want)
	}
	if source != "collected journal for lab-proxmox-01" {
		t.Fatalf("Proxmox remote journal source = %q", source)
	}
}

func TestJournalQueryUsesCollectorLocalJournalForCollector(t *testing.T) {
	collector := model.Component{Name: "lab-log-01", Hostname: "lab-log-01", Address: "10.10.10.40"}
	got, source := journalQuery(collector, collector, 10, "", "", "")
	want := []string{"journalctl", "--no-pager", "--output=short-iso", "--lines=10", "_HOSTNAME=lab-log-01"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("collector-local journal query = %#v, want %#v", got, want)
	}
	if source != "collector-local journal" {
		t.Fatalf("collector-local source = %q", source)
	}
}

func TestFindManagedEndpointIncludesRetainedModuleGuest(t *testing.T) {
	site := model.NewSite("installation", "age1example", model.GatewayModeManaged)
	retained := model.Component{
		Name: "lab-monitor-01", Hostname: "lab-monitor-01", Address: "10.10.10.20",
		Module: "monitoring", ProductOwned: true,
	}
	site.RetainedModules = []model.RetainedModule{{Module: "monitoring", Disposition: "retained", Guests: []model.Component{retained}}}
	got, ok := findManagedEndpoint(site, "lab-monitor-01")
	if !ok || got.Name != retained.Name || got.Address != retained.Address {
		t.Fatalf("retained endpoint lookup = %#v, %t", got, ok)
	}
}
