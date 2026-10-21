package labspeedtest

import (
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
