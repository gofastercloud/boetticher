package cli

import (
	"io"
	"strings"
	"testing"
)

func TestLogsRejectsMultipleHostsBeforeLoadingSite(t *testing.T) {
	err := runLogs([]string{"lab-dns-01", "lab-dns-02"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "at most one managed HOST") {
		t.Fatalf("multiple log hosts were not rejected: %v", err)
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
