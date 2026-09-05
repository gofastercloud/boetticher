package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/firewall"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	"github.com/gofastercloud/boetticher/internal/networktest"
)

func TestProbeAddressModeUsesDHCPOnlyForDynamicZones(t *testing.T) {
	for _, test := range []struct {
		mode string
		want string
	}{
		{mode: "static", want: "manual"},
		{mode: "reservations-only", want: "manual"},
		{mode: "dynamic-reservations", want: "dhcp"},
		{mode: "dynamic", want: "dhcp"},
	} {
		if got := probeAddressMode(networktest.Probe{AddressMode: test.mode}); got != test.want {
			t.Errorf("address mode %q = %q, want %q", test.mode, got, test.want)
		}
	}
}

func TestGatewayProbeSkipsManagedTRANSITDiagnosticICMP(t *testing.T) {
	if gatewayProbeExpected("TRANSIT") {
		t.Fatal("TRANSIT gateway ICMP was treated as an expected allow")
	}
	if gatewayProbeExpected("SANDBOX") {
		t.Fatal("SANDBOX gateway diagnostics must be denied")
	}
	for _, zone := range []string{"INFRA", "SERVERS", "TRUSTED", "MGMT"} {
		if !gatewayProbeExpected(zone) {
			t.Fatalf("%s gateway ICMP was not treated as an expected allow", zone)
		}
	}
}

func TestProbeDNSNameRespectsSANDBOXNamespaceIsolation(t *testing.T) {
	if got := probeDNSName("SANDBOX", "lab.home.arpa"); got != "example.com" {
		t.Fatalf("SANDBOX DNS probe name = %q, want example.com", got)
	}
	if got := probeDNSName("TRUSTED", "lab.home.arpa"); got != "monitor.lab.home.arpa" {
		t.Fatalf("private-zone DNS probe name = %q, want monitor.lab.home.arpa", got)
	}
}

func TestPolicyAllowsHonorsSourceAndDestinationCIDRs(t *testing.T) {
	policy := firewall.Plan{Rules: []firewall.PolicyRule{{
		From: "TRUSTED", To: "INFRA", Action: "allow", Protocol: "tcp", Ports: []string{"443"},
		SourceCIDR: "10.10.30.250/32", DestinationCIDR: "10.10.10.30/32",
	}}}
	if !policyAllows(policy, "TRUSTED", "INFRA", "tcp", 443, "10.10.30.250", "10.10.10.30") {
		t.Fatal("matching source and destination was denied")
	}
	if policyAllows(policy, "TRUSTED", "INFRA", "tcp", 443, "10.10.30.251", "10.10.10.30") {
		t.Fatal("non-matching source CIDR was allowed")
	}
}
func TestPolicyAllowsBuiltInHTTPSForDynamicTrustedProbeAddress(t *testing.T) {
	plan, err := firewall.PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"10.10.30.106", "10.10.30.199"} {
		if !policyAllows(plan, "TRUSTED", "INFRA", "tcp", 443, address, "10.10.10.20") {
			t.Fatalf("Pulse HTTPS was denied for dynamic TRUSTED probe address %s", address)
		}
	}
}

func TestAirVPNNetworkTestRequiresDeclaredARRAndAirVPNContracts(t *testing.T) {
	if err := validateAirVPNNetworkTestSite(model.NewDefaultSite("installation", "age1example")); err == nil {
		t.Fatal("AirVPN test accepted a site without enabled AirVPN and ARR modules")
	}
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	enabled := true
	config.Modules.AirVPN = &model.AirVPNModuleConfig{Enabled: &enabled, Servers: "australia"}
	config.Modules.Arr = &model.ArrModuleConfig{Enabled: &enabled, Network: model.ModuleNetworkAirVPN}
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAirVPNNetworkTestSite(site); err != nil {
		t.Fatalf("AirVPN test rejected the declared ARR and AirVPN contracts: %v", err)
	}
}

func TestParsePublicIPv4RejectsNonPublicAndMalformedValues(t *testing.T) {
	if got, err := parsePublicIPv4("8.8.8.8\n"); err != nil || got != "8.8.8.8" {
		t.Fatalf("public IPv4 = %q, %v", got, err)
	}
	for _, value := range []string{"", "10.10.20.110", "127.0.0.1", "169.254.1.1", "2001:db8::1", "8.8.8.8 extra"} {
		if _, err := parsePublicIPv4(value); err == nil {
			t.Fatalf("non-public or malformed probe output %q was accepted", value)
		}
	}
}

func TestResponseDetailPreservesProbeOutputWhenExecutionFails(t *testing.T) {
	detail := responseDetail(probeResponse{
		Error:  "curl exited with status 28",
		Output: "http_code=000 time=5.000000",
	}, errors.New("exit status 1"))
	for _, want := range []string{"curl exited with status 28", "http_code=000 time=5.000000", "exit status 1"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("response detail %q omitted %q", detail, want)
		}
	}
}

func TestNetworkProbeOwnershipUsesExactTagsAndDescriptionFields(t *testing.T) {
	if !hasExactProxmoxTag("boetticher;managed;boetticher-network-probe", "boetticher-network-probe") {
		t.Fatal("canonical network-probe tag was not recognized")
	}
	for _, tags := range []string{"boetticher;managed;not-boetticher-network-probe", "boetticher-network-probe-foreign"} {
		if hasExactProxmoxTag(tags, "boetticher-network-probe") {
			t.Fatalf("foreign tag %q was accepted", tags)
		}
	}
	if !hasExactDescriptionField("boetticher-network-probe installation=installation-01 run=run-01", "installation", "installation-01") {
		t.Fatal("canonical installation description field was not recognized")
	}
	for _, description := range []string{
		"boetticher-network-probe installation=installation-01-foreign",
		"boetticher-network-probe preinstallation=installation-01",
	} {
		if hasExactDescriptionField(description, "installation", "installation-01") {
			t.Fatalf("foreign description %q was accepted", description)
		}
	}
}

func TestFinishNetworkTestRendersBinaryOperatorResults(t *testing.T) {
	report := networktest.Report{
		RunID:   "run-1",
		Overall: "INCONCLUSIVE",
		Cleanup: "HOLD: reserved VMID 910 is occupied by an unknown guest",
		Results: []networktest.Result{
			{Name: "tcp/TRUSTED/monitor", Status: "INCONCLUSIVE", Detail: "HOLD: the path could not be established"},
		},
	}
	var output bytes.Buffer
	if err := finishNetworkTest(&output, false, report, nil); err == nil {
		t.Fatal("finishNetworkTest() error = nil, want failure")
	}
	text := output.String()
	for _, forbidden := range []string{"HOLD", "INCONCLUSIVE", "NOT TESTED", "NOT VERIFIED", "PARTIAL", "UNKNOWN"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("human output exposed %q: %s", forbidden, text)
		}
	}
	for _, want := range []string{"Network test run-1: FAIL", "FAIL         tcp/TRUSTED/monitor", "Cleanup: FAIL", "Reason:"} {
		if !strings.Contains(text, want) {
			t.Fatalf("human output missing %q: %s", want, text)
		}
	}
}

func TestFinishNetworkTestKeepsRichStatusesInJSON(t *testing.T) {
	report := networktest.Report{RunID: "run-2", Overall: "INCONCLUSIVE", Cleanup: "HOLD: cleanup failed", Results: []networktest.Result{{Name: "iperf/one/two/tcp", Status: "INCONCLUSIVE"}}}
	var output bytes.Buffer
	if err := finishNetworkTest(&output, true, report, nil); err == nil {
		t.Fatal("finishNetworkTest() error = nil, want failure")
	}
	if !strings.Contains(output.String(), `"overall": "INCONCLUSIVE"`) || !strings.Contains(output.String(), `"status": "INCONCLUSIVE"`) {
		t.Fatalf("JSON output lost rich evidence: %s", output.String())
	}
}

func TestNetworkTestProgressRendersDurationsAndBinaryResults(t *testing.T) {
	var output bytes.Buffer
	progress := newNetworkTestProgress(&output, 2)
	progress.start("Prepare probes")
	progress.complete()
	progress.start("Run path checks")
	progress.fail(errors.New("HOLD: one or more checks need attention"))

	text := output.String()
	for _, want := range []string{"[1/2] Prepare probes", "PASS (", "[2/2] Run path checks", "FAIL: one or more checks need attention"} {
		if !strings.Contains(text, want) {
			t.Fatalf("network progress omitted %q:\n%s", want, text)
		}
	}
	for _, forbidden := range []string{"HOLD", "INCONCLUSIVE", "NOT TESTED", "NOT VERIFIED", "PARTIAL", "UNKNOWN"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("network progress exposed %q:\n%s", forbidden, text)
		}
	}
}
