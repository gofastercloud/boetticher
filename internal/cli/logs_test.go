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
