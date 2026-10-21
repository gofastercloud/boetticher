package labspeedtest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseEventAcceptsEachPhase(t *testing.T) {
	for _, line := range []string{
		`{"phase":"setup","recovered_leftovers":true}`,
		`{"phase":"server","server":"Example (Sydney)"}`,
		`{"phase":"ping","latency_ms":9.5,"jitter_ms":1.2}`,
		`{"phase":"download","download_mbps":412.3}`,
		`{"phase":"upload","upload_mbps":38}`,
		`{"phase":"done","server":"Example","latency_ms":9,"download_mbps":600,"upload_mbps":40}`,
		`{"phase":"error","error":"speedtest ping: timeout"}`,
	} {
		if _, err := ParseEvent([]byte(line)); err != nil {
			t.Errorf("ParseEvent(%s) = %v", line, err)
		}
	}
}

func TestParseEventRejectsMalformedProgress(t *testing.T) {
	for _, line := range []string{
		``,
		`not json`,
		`{"phase":"warp"}`,
		`{"phase":"download","download_mbps":-1}`,
		`{"phase":"download","download_mbps":1e12}`,
		`{"phase":"done","upload_mbps":40}`,
		`{"phase":"error"}`,
		`{"phase":"ping","error":"x"}`,
		`{"phase":"ping","extra":1}`,
		`{"phase":"ping"} {"phase":"ping"}`,
		`{"phase":"server","server":"` + strings.Repeat("x", 300) + `"}`,
		`{"phase":"setup","pad":"` + strings.Repeat("x", MaxEventBytes) + `"}`,
	} {
		if _, err := ParseEvent([]byte(line)); err == nil {
			t.Errorf("ParseEvent(%q) accepted malformed progress", line)
		}
	}
}

func TestEncodeRoundTripsAndBoundsErrors(t *testing.T) {
	event := ErrorEvent("%s", strings.Repeat("very long failure ", 100))
	data, err := Encode(event)
	if err != nil {
		t.Fatal(err)
	}
	if data[len(data)-1] != '\n' || len(data) > MaxEventBytes {
		t.Fatalf("encoded error is not one bounded line: %d bytes", len(data))
	}
	decoded, err := ParseEvent(data)
	if err != nil || decoded.Phase != PhaseError || !decoded.Terminal() {
		t.Fatalf("round trip = %#v, %v", decoded, err)
	}
	if _, err := Encode(Event{Phase: PhaseDone}); err == nil {
		t.Fatal("done event without a download result was encodable")
	}
}

func TestCleanupEventsAreTerminalAndHelperAbsentIsCleanupOnly(t *testing.T) {
	for _, line := range []string{`{"phase":"cleanup"}`, `{"phase":"cleanup","recovered_leftovers":true}`, `{"phase":"cleanup","helper_absent":true}`} {
		event, err := ParseEvent([]byte(line))
		if err != nil || !event.Terminal() {
			t.Fatalf("ParseEvent(%s) = %#v, %v", line, event, err)
		}
	}
	if _, err := ParseEvent([]byte(`{"phase":"setup","helper_absent":true}`)); err == nil {
		t.Fatal("helper_absent accepted outside cleanup")
	}
}

// The cleanup command must not fail on a Host still running the v1 helper,
// which has no lab mode and so cannot own a fixture.
func TestCleanupCommandHandlesStaleAndCurrentHelpers(t *testing.T) {
	for name, item := range map[string]struct {
		helper string
		want   string
	}{
		"v1 helper":      {helper: "#!/bin/sh\necho 'flag provided but not defined: -version' >&2\nexit 2\n", want: `{"phase":"cleanup","helper_absent":true}`},
		"missing helper": {want: `{"phase":"cleanup","helper_absent":true}`},
		"v2 helper":      {helper: "#!/bin/sh\nif [ \"$1\" = --version ]; then echo " + HelperVersion + "; exit 0; fi\necho \"ran $*\"\n", want: "ran --lab --cleanup-only"},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "boetticher-host-speedtest")
			if item.helper != "" {
				if err := os.WriteFile(path, []byte(item.helper), 0700); err != nil {
					t.Fatal(err)
				}
			}
			output, err := exec.Command("/bin/sh", "-c", strings.ReplaceAll(CleanupCommand, HelperPath, path)).Output()
			if err != nil || strings.TrimSpace(string(output)) != item.want {
				t.Fatalf("output=%q err=%v", output, err)
			}
		})
	}
}
