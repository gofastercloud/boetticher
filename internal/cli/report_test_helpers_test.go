package cli

import (
	"strings"
	"testing"
)

func assertNoHumanEvidenceStates(t *testing.T, text string) {
	t.Helper()
	for _, forbidden := range []string{"HOLD", "NOT TESTED", "NOT VERIFIED", "PARTIAL", "INCONCLUSIVE", "UNKNOWN"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("human deployment report contains forbidden result state %q:\n%s", forbidden, text)
		}
	}
}
