package cli

import "testing"

func TestDeniedNetworkProbeRequiresCompletedMeasurement(t *testing.T) {
	if probeOutcome(probeResponse{}, false) != "FAIL" {
		t.Fatal("missing transport response was accepted as isolation")
	}
	if probeOutcome(probeResponse{Completed: true, OK: false}, false) != "PASS" {
		t.Fatal("completed denied packet measurement was rejected")
	}
	if probeOutcome(probeResponse{Completed: true, OK: true}, false) != "FAIL" {
		t.Fatal("permitted packet was accepted as isolated")
	}
}

func TestAuthorizedProbeRejectsHTTPErrorPages(t *testing.T) {
	for _, value := range []string{"http_code=400", "http_code=401", "http_code=403", "http_code=404", "http_code=500", "http_code=000"} {
		if probeHTTPAuthorized(value) {
			t.Fatalf("accepted failed application response %s", value)
		}
	}
	if !probeHTTPAuthorized("http_code=200 time=0.01") {
		t.Fatal("valid authorized response rejected")
	}
}
