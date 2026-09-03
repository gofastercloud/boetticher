package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/artifacts"
	"github.com/gofastercloud/boetticher/internal/firewall"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/networktest"
	"github.com/gofastercloud/boetticher/internal/pki"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/site"
	"github.com/gofastercloud/boetticher/internal/storage"
)

const (
	networkProbeHostCommand   = "/usr/lib/boetticher/boetticher-network-probe-host"
	networkTestPrepareTimeout = 5 * time.Minute
	networkTestCasesTimeout   = 10 * time.Minute
	networkTestCleanupTimeout = 5 * time.Minute
	airVPNProbeURL            = "https://api.ipify.org"
	airVPNProbeAttempts       = 12
	airVPNProbeInterval       = 5 * time.Second
)

type probeResponse struct {
	OK           bool              `json:"ok"`
	ExitCode     int               `json:"exit_code,omitempty"`
	Output       string            `json:"output,omitempty"`
	Measurements map[string]string `json:"measurements,omitempty"`
	Error        string            `json:"error,omitempty"`
}

func runNetworkTest(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("network test", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	zones := fs.String("zones", "", "comma-separated network zones; defaults to all zones")
	capture := fs.Bool("capture", false, "include bounded tcpdump output from each probe")
	cleanupOnly := fs.Bool("cleanup-only", false, "remove stale exact-owned probe guests")
	airvpn := fs.Bool("airvpn", false, "exercise ARR AirVPN egress and the tunnel-down fail-closed path")
	jsonOutput := fs.Bool("json", false, "emit the versioned report as JSON")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	proxmoxCA := fs.String("proxmox-ca", "", "Proxmox API CA PEM file")
	insecure := fs.Bool("insecure", false, "explicitly allow self-signed Proxmox API TLS")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cleanupOnly && *airvpn {
		return errors.New("--airvpn cannot be combined with --cleanup-only")
	}
	progressTotal := 6
	if *cleanupOnly {
		progressTotal = 2
	} else if *airvpn {
		progressTotal++
	}
	progress := newNetworkTestProgress(out, progressTotal)
	progress.start("Validate site and select zones")
	s, err := site.Load(*siteDir)
	if err != nil {
		progress.fail(err)
		return err
	}
	if err := s.Validate(); err != nil {
		progress.fail(err)
		return err
	}
	if *airvpn {
		if err := validateAirVPNNetworkTestSite(s); err != nil {
			progress.fail(err)
			return err
		}
	}
	modelRevision, err := s.Revision()
	if err != nil {
		progress.fail(err)
		return err
	}
	if !*cleanupOnly && s.Gateway.Mode == model.GatewayModeExternal && s.PhysicalNetwork.Mode == model.ModeVirtualOnly {
		progress.fail(errors.New("network test requires the declared physical VLAN trunk in external-firewall mode"))
		return errors.New("network test requires the declared physical VLAN trunk in external-firewall mode")
	}
	selectedZones, err := networktest.SelectZones(s, *zones)
	if err != nil {
		progress.fail(err)
		return err
	}
	progress.complete()
	runID := networkTestRunID()
	if *cleanupOnly {
		progress.start("Remove stale exact-owned probes")
		client, _, clientErr := loadProxmoxClient(*siteDir, s, *ageIdentity, *proxmoxCA, *insecure)
		if clientErr != nil {
			progress.fail(clientErr)
			return clientErr
		}
		node, nodeErr := client.SingleNode(context.Background())
		if nodeErr != nil {
			progress.fail(nodeErr)
			return nodeErr
		}
		cleanupErr := cleanupNetworkProbes(context.Background(), client, node, s, nil)
		if cleanupErr != nil {
			progress.fail(cleanupErr)
		} else {
			progress.complete()
		}
		if cleanupErr != nil {
			return networkTestOperatorError{cause: cleanupErr}
		}
		fmt.Fprintln(out, "Network cleanup: PASS")
		return nil
	}
	progress.start("Resolve qualified probe artifact")
	probes, err := networktest.Plans(s, selectedZones, runID)
	if err != nil {
		progress.fail(err)
		return err
	}
	definition, ok := artifacts.Lookup("network-probe")
	if !ok {
		err := errors.New("network probe artifact definition is unavailable")
		progress.fail(err)
		return err
	}
	wantedArtifact, err := artifacts.ArtifactFor("network-probe")
	if err != nil {
		progress.fail(err)
		return err
	}
	artifact, evidence, err := artifacts.ResolveArtifactEvidence(*siteDir, wantedArtifact)
	if err != nil {
		err = fmt.Errorf("network probe artifact is not qualified: %w", err)
		progress.fail(err)
		return err
	}
	progress.complete()
	progress.start("Prepare Proxmox probe environment")
	client, _, err := loadProxmoxClient(*siteDir, s, *ageIdentity, *proxmoxCA, *insecure)
	if err != nil {
		progress.fail(err)
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), networkTestPrepareTimeout)
	defer cancel()
	node, err := client.SingleNode(ctx)
	if err != nil {
		progress.fail(err)
		return err
	}
	if err := cleanupNetworkProbes(ctx, client, node, s, probes); err != nil {
		progress.fail(err)
		return err
	}
	if err := ensureNetworkProbeArtifact(ctx, client, node, evidence.ArtifactPath, artifact); err != nil {
		progress.fail(err)
		return err
	}
	policy, err := firewall.PlanFromSite(s)
	if err != nil {
		err = fmt.Errorf("plan network test policy: %w", err)
		progress.fail(err)
		return err
	}
	storagePlan, err := storage.PlanFromSite(s)
	if err != nil {
		progress.fail(err)
		return err
	}
	progress.complete()
	report := networktest.Report{Version: definition.Version, RunID: runID, ModelRevision: modelRevision, Mode: string(s.Gateway.Mode), Probes: probes, Cleanup: "PENDING", Overall: "HOLD", EvidencePath: filepath.Join(site.RuntimeDir(s), "network-tests", runID, "report.json")}
	progress.start("Create and start temporary probes")
	created := make([]networktest.Probe, 0, len(probes))
	var runErr error
	for index := range probes {
		probe := &probes[index]
		if err := createNetworkProbe(ctx, client, node, storagePlan.GuestStorage, artifact, s, *probe, runID); err != nil {
			report.Results = append(report.Results, networktest.Result{Name: "probe/" + probe.Zone, Status: "HOLD", Detail: err.Error(), Started: time.Now().UTC().Format(time.RFC3339), Finished: time.Now().UTC().Format(time.RFC3339)})
			runErr = err
			break
		}
		fmt.Fprintf(out, "      PASS probe/%s created\n", probe.Zone)
		created = append(created, *probe)
		if err := startNetworkProbe(ctx, client, node, *siteDir, s, probe, artifact.ContentSHA256, runID); err != nil {
			runErr = err
			break
		}
		created[index] = *probe
	}
	if runErr != nil {
		progress.fail(runErr)
	} else {
		progress.complete()
	}
	if runErr == nil {
		progress.start("Run bounded path checks")
	}
	if runErr == nil {
		caseCtx, cancelCases := context.WithTimeout(context.Background(), networkTestCasesTimeout)
		defer cancelCases()
		authority, authorityErr := site.LoadAuthority(*siteDir, s, *ageIdentity)
		if authorityErr != nil {
			runErr = fmt.Errorf("load mTLS authority: %w", authorityErr)
		} else {
			cert, certErr := pki.IssueClient(authority, "network-test-"+runID[len(runID)-6:], s.Network.Domain, time.Now().UTC())
			if certErr != nil {
				runErr = fmt.Errorf("issue short-lived network-test client: %w", certErr)
			} else {
				for index := range created {
					before := len(report.Results)
					if err := runNetworkProbeCases(caseCtx, *siteDir, s, policy, &created[index], created, artifact.ContentSHA256, runID, authority.RootCertPEM+authority.IssuingCertPEM, cert, *capture, &report); err != nil {
						runErr = err
						break
					}
					zoneResults := report.Results[before:]
					fmt.Fprintf(out, "      %s %s (%d cases)\n", operatorNetworkTestStatus(networkTestOverall(zoneResults, nil)), created[index].Zone, len(zoneResults))
				}
			}
		}
	}
	if runErr != nil && progress.active {
		progress.fail(runErr)
	} else if progress.active {
		if networkTestOverall(report.Results, nil) == "PASS" {
			progress.complete()
		} else {
			progress.fail(errors.New("one or more bounded path checks failed; review the case details"))
		}
	}
	if runErr == nil && *airvpn {
		progress.start("Probe AirVPN egress and fail-closed safeguards")
		airVPNCtx, cancelAirVPN := context.WithTimeout(context.Background(), networkTestCasesTimeout)
		err := runAirVPNNetworkProbe(airVPNCtx, client, node, *siteDir, s, &report)
		cancelAirVPN()
		if err != nil {
			runErr = err
			progress.fail(err)
		} else {
			progress.complete()
		}
	}
	report.Probes = created
	progress.start("Remove temporary probes")
	cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), networkTestCleanupTimeout)
	defer cancelCleanup()
	cleanupErr := cleanupNetworkProbes(cleanupCtx, client, node, s, probes)
	if cleanupErr != nil {
		report.Cleanup = "HOLD: " + cleanupErr.Error()
		progress.fail(cleanupErr)
	} else {
		report.Cleanup = "PASS"
		progress.complete()
	}
	report.Overall = networkTestOverall(report.Results, cleanupErr)
	if runErr != nil && report.Overall == "PASS" {
		report.Overall = "HOLD"
	}
	if runErr == nil && cleanupErr != nil {
		runErr = cleanupErr
	}
	if writeErr := writeNetworkTestReport(s, report); writeErr != nil {
		report.Overall = "HOLD"
		if runErr == nil {
			runErr = fmt.Errorf("write network test evidence: %w", writeErr)
		}
	}
	return finishNetworkTest(out, *jsonOutput, report, runErr)
}

func networkTestRunID() string {
	var random [3]byte
	_, _ = rand.Read(random[:])
	return strings.ToLower(time.Now().UTC().Format("20060102t150405") + "-" + hex.EncodeToString(random[:]))
}

func ensureNetworkProbeArtifact(ctx context.Context, client *proxmox.Client, node, source string, artifact model.Artifact) error {
	filename := artifact.Name + "-" + artifact.Version + "-" + artifact.Architecture + ".tar.zst"
	contents, err := client.StorageContent(ctx, node, "local", "vztmpl")
	if err != nil {
		return fmt.Errorf("inspect network probe template storage: %w", err)
	}
	for _, content := range contents {
		if content.Filename != filename {
			continue
		}
		if !strings.EqualFold(content.Checksum, artifact.ContentSHA256) {
			return fmt.Errorf("existing network probe template has a different checksum")
		}
		return nil
	}
	if err := client.UploadStorageFile(ctx, node, "local", "vztmpl", source, filename, artifact.ContentSHA256); err != nil {
		return fmt.Errorf("upload qualified network probe template: %w", err)
	}
	return nil
}

func createNetworkProbe(ctx context.Context, client *proxmox.Client, node, guestStorage string, artifact model.Artifact, s model.Site, probe networktest.Probe, runID string) error {
	if err := networktest.ValidateProbeAddress(probe); err != nil {
		return err
	}
	params := mapToValues(map[string]string{
		"hostname":    probe.Hostname,
		"description": fmt.Sprintf("boetticher-network-probe installation=%s run=%s zone=%s artifact=%s", s.SecretMetadata.InstallationID, runID, probe.Zone, artifact.ContentSHA256),
		"ostemplate":  "local:vztmpl/" + artifact.Name + "-" + artifact.Version + "-" + artifact.Architecture + ".tar.zst",
		"memory":      "256", "cores": "1", "unprivileged": "1", "onboot": "0", "features": "nesting=0",
		"rootfs": guestStorage + ":2", "tags": "boetticher;managed;" + networktest.HarnessTag,
		"net0": fmt.Sprintf("name=eth0,bridge=vmbr1,tag=%d,firewall=1,hwaddr=%s,ip=%s", probe.VLAN, probe.MAC, probeAddressMode(probe)),
	})
	if err := client.CreateLXC(ctx, node, probe.VMID, params); err != nil {
		return fmt.Errorf("create network probe %s: %w", probe.Zone, err)
	}
	kind, current, err := client.GuestConfig(ctx, node, probe.VMID)
	if err != nil || kind != proxmox.KindLXC {
		return fmt.Errorf("verify network probe %s after creation: %w", probe.Zone, err)
	}
	if current["hostname"] != probe.Hostname {
		return fmt.Errorf("created network probe %s has the wrong hostname", probe.Zone)
	}
	return nil
}

func startNetworkProbe(ctx context.Context, client *proxmox.Client, node, siteDir string, s model.Site, probe *networktest.Probe, artifactDigest, runID string) error {
	if err := client.StartLXC(ctx, node, probe.VMID); err != nil {
		return fmt.Errorf("start network probe %s: %w", probe.Zone, err)
	}
	for attempt := 0; attempt < 12; attempt++ {
		status, err := client.LXCStatus(ctx, node, probe.VMID)
		if err == nil && status == "running" {
			break
		}
		if attempt == 11 {
			return fmt.Errorf("network probe %s did not reach running state", probe.Zone)
		}
		timer := time.NewTimer(time.Second)
		<-timer.C
	}
	runner := networkProbeRunner(s, siteDir)
	if probe.Address != "" {
		arping, err := executeNetworkProbe(ctx, runner, s, *probe, artifactDigest, runID, map[string]any{"version": 1, "kind": "arping", "target": probe.Address})
		if err != nil || !arping.OK {
			return fmt.Errorf("duplicate-address detection failed for %s: %s", probe.Zone, responseDetail(arping, err))
		}
		static := fmt.Sprintf("name=eth0,bridge=vmbr1,tag=%d,firewall=1,hwaddr=%s,ip=%s/24,gw=%s", probe.VLAN, probe.MAC, probe.Address, probe.Gateway)
		if err := client.SetLXCConfig(ctx, node, probe.VMID, mapToValues(map[string]string{"net0": static})); err != nil {
			return fmt.Errorf("configure static address for %s: %w", probe.Zone, err)
		}
		for _, step := range []map[string]any{{"version": 1, "kind": "configure", "target": probe.Address}, {"version": 1, "kind": "route", "target": probe.Gateway}} {
			if result, err := executeNetworkProbe(ctx, runner, s, *probe, artifactDigest, runID, step); err != nil || !result.OK {
				return fmt.Errorf("configure network probe %s: %s", probe.Zone, responseDetail(result, err))
			}
		}
	}
	for attempt := 0; attempt < 12; attempt++ {
		result, err := executeNetworkProbe(ctx, runner, s, *probe, artifactDigest, runID, map[string]any{"version": 1, "kind": "identity"})
		if err == nil && result.OK {
			if address := probeAddress(result.Output); address != "" {
				probe.Address = address
				return nil
			}
		}
		timer := time.NewTimer(time.Second)
		<-timer.C
	}
	return fmt.Errorf("network probe %s did not expose an IPv4 address", probe.Zone)
}

func probeAddressMode(probe networktest.Probe) string {
	if probe.AddressMode == "dynamic" || probe.AddressMode == "dynamic-reservations" {
		return "dhcp"
	}
	return "manual"
}

func runNetworkProbeCases(ctx context.Context, siteDir string, s model.Site, policy firewall.Plan, source *networktest.Probe, probes []networktest.Probe, digest, runID, ca string, cert pki.ClientCertificate, capture bool, report *networktest.Report) error {
	runner := networkProbeRunner(s, siteDir)
	add := func(name, kind, target string, port int, expected bool, payload map[string]any) {
		started := time.Now().UTC()
		response, err := executeNetworkProbe(ctx, runner, s, *source, digest, runID, payload)
		status := "PASS"
		if (err != nil || !response.OK) == expected {
			status = "FAIL"
		}
		report.Results = append(report.Results, networktest.Result{Name: name, Kind: kind, Source: source.Zone, Target: target, Status: status, Detail: responseDetail(response, err), Started: started.Format(time.RFC3339), Finished: time.Now().UTC().Format(time.RFC3339)})
	}
	if gatewayProbeExpected(source.Zone) {
		add("gateway/"+source.Zone, "ping", source.Gateway, 0, true, map[string]any{"version": 1, "kind": "ping", "target": source.Gateway})
	}
	dnsName := probeDNSName(source.Zone, s.Network.Domain)
	for _, dnsServer := range zoneDNS(s, source.Zone) {
		add("dns/"+source.Zone+"/"+dnsServer, "dns", dnsServer, 53, true, map[string]any{"version": 1, "kind": "dns", "target": dnsServer, "name": dnsName, "type": "A"})
	}
	for _, component := range s.PlatformComponents() {
		if component.Address == "" || component.URL == "" {
			continue
		}
		endpoint, err := url.Parse(component.URL)
		if err != nil {
			continue
		}
		port := 443
		if endpoint.Port() != "" {
			port, _ = strconv.Atoi(endpoint.Port())
		}
		allowed := policyAllows(policy, source.Zone, component.Zone, "tcp", port, source.Address, component.Address)
		add("tcp/"+source.Zone+"/"+component.Name, "tcp", component.Address, port, allowed, map[string]any{"version": 1, "kind": "tcp", "target": component.Address, "port": port})
		add("nmap/"+source.Zone+"/"+component.Name, "nmap", component.Address, port, allowed, map[string]any{"version": 1, "kind": "nmap", "target": component.Address, "port": port})
		if component.MTLS && allowed {
			started := time.Now().UTC()
			negative, negativeErr := executeNetworkProbe(ctx, runner, s, *source, digest, runID, map[string]any{"version": 1, "kind": "mtls", "target": component.Address, "url": component.URL, "ca": ca})
			negativeStatus := "PASS"
			if negativeErr != nil || !negative.OK || !mtlsDenied(negative.Output) {
				negativeStatus = "FAIL"
			}
			report.Results = append(report.Results, networktest.Result{Name: "mtls/no-client/" + component.Name, Kind: "mtls", Source: source.Zone, Target: component.Name, Status: negativeStatus, Detail: responseDetail(negative, negativeErr), Started: started.Format(time.RFC3339), Finished: time.Now().UTC().Format(time.RFC3339)})
			started = time.Now().UTC()
			positive, positiveErr := executeNetworkProbe(ctx, runner, s, *source, digest, runID, map[string]any{"version": 1, "kind": "mtls", "target": component.Address, "url": component.URL, "ca": ca, "cert": cert.ChainPEM, "key": cert.KeyPEM})
			positiveStatus := "PASS"
			if positiveErr != nil || !positive.OK || strings.Contains(positive.Output, "http_code=000") {
				positiveStatus = "FAIL"
			}
			report.Results = append(report.Results, networktest.Result{Name: "mtls/client/" + component.Name, Kind: "mtls", Source: source.Zone, Target: component.Name, Status: positiveStatus, Detail: responseDetail(positive, positiveErr), Started: started.Format(time.RFC3339), Finished: time.Now().UTC().Format(time.RFC3339)})
		}
	}
	for _, target := range probes {
		if target.Zone == source.Zone || target.Address == "" || !policyAllows(policy, source.Zone, target.Zone, "tcp", 443, source.Address, target.Address) {
			continue
		}
		iperfNetworkProbe(ctx, runner, s, *source, target, digest, runID, 443, "tcp", report)
		if target.Zone == "INFRA" && policyAllows(policy, source.Zone, target.Zone, "udp", 53, source.Address, target.Address) {
			iperfNetworkProbe(ctx, runner, s, *source, target, digest, runID, 53, "udp", report)
		}
	}
	if capture {
		add("capture/"+source.Zone, "capture", source.Gateway, 0, true, map[string]any{"version": 1, "kind": "capture", "target": source.Gateway})
	}
	return nil
}

func gatewayProbeExpected(zone string) bool {
	// TRANSIT is an isolated routed edge. The managed gateway intentionally
	// does not accept diagnostic ICMP from transit0; the other client-facing
	// zones do. The probe still validates the TRANSIT route through its
	// modeled downstream cases.
	return zone != "TRANSIT"
}

func iperfNetworkProbe(ctx context.Context, runner proxmox.SSHRunner, s model.Site, source, target networktest.Probe, digest, runID string, port int, protocol string, report *networktest.Report) {
	started := time.Now().UTC()
	serverDone := make(chan probeResponse, 1)
	go func() {
		result, err := executeNetworkProbe(ctx, runner, s, target, digest, runID, map[string]any{"version": 1, "kind": "iperf-server", "port": port, "type": protocol})
		if err != nil {
			result.Error = err.Error()
		}
		serverDone <- result
	}()
	time.Sleep(300 * time.Millisecond)
	clientResult, clientErr := executeNetworkProbe(ctx, runner, s, source, digest, runID, map[string]any{"version": 1, "kind": "iperf-client", "target": target.Address, "port": port, "type": protocol})
	serverResult := <-serverDone
	if clientErr != nil {
		clientResult.Error = clientErr.Error()
	}
	status := "PASS"
	if clientErr != nil || !clientResult.OK || !serverResult.OK {
		status = "INCONCLUSIVE"
	}
	report.Results = append(report.Results, networktest.Result{Name: "iperf/" + source.Zone + "/" + target.Zone + "/" + protocol, Kind: "iperf3", Source: source.Zone, Target: target.Zone, Status: status, Detail: responseDetail(clientResult, clientErr), Started: started.Format(time.RFC3339), Finished: time.Now().UTC().Format(time.RFC3339)})
}

func executeNetworkProbe(ctx context.Context, runner proxmox.SSHRunner, s model.Site, probe networktest.Probe, digest, runID string, payload map[string]any) (probeResponse, error) {
	data, err := json.Marshal(map[string]any{"version": 1, "action": "run", "vmid": probe.VMID, "installation_id": s.SecretMetadata.InstallationID, "run_id": runID, "zone": probe.Zone, "artifact_sha256": digest, "payload": payload})
	if err != nil {
		return probeResponse{}, err
	}
	output, runErr := runner.RunWithStdin(ctx, s.BootstrapAddress, "lab-netprobe", networkProbeHostCommand, bytes.NewReader(data))
	var response probeResponse
	if len(bytes.TrimSpace(output)) > 0 {
		if err := json.Unmarshal(output, &response); err != nil && runErr == nil {
			return response, fmt.Errorf("decode network probe response: %w", err)
		}
	}
	return response, runErr
}

func networkProbeRunner(s model.Site, siteDir string) proxmox.SSHRunner {
	return proxmox.SSHRunner{IdentityFile: operatorIdentityFile(s), ConfigFile: filepath.Join(siteDir, "generated", "ssh", "boetticher.conf"), KnownHosts: deploymentKnownHosts(siteDir), StrictHostKey: "yes", HostAlias: model.LogicalProxmoxIdentity, HostKeyAlias: model.LogicalProxmoxIdentity}
}

func probeAddress(output string) string {
	var interfaces []struct {
		AddrInfo []struct{ Family, Local string } `json:"addr_info"`
	}
	if json.Unmarshal([]byte(output), &interfaces) != nil {
		return ""
	}
	for _, iface := range interfaces {
		for _, addr := range iface.AddrInfo {
			if addr.Family == "inet" && addr.Local != "127.0.0.1" && net.ParseIP(addr.Local) != nil {
				return addr.Local
			}
		}
	}
	return ""
}

func zoneDNS(s model.Site, name string) []string {
	for _, zone := range s.Network.Zones {
		if zone.Name == name {
			return zone.DNSAddresses
		}
	}
	return nil
}

func probeDNSName(zone, domain string) string {
	if zone == "SANDBOX" {
		// SANDBOX intentionally cannot resolve the private platform namespace;
		// its gateway resolver is a public forwarder with a local sandbox zone.
		return "example.com"
	}
	return "monitor." + domain
}

func policyAllows(policy firewall.Plan, source, target, protocol string, port int, sourceAddress, destinationAddress string) bool {
	if source == target {
		return true
	}
	for _, rule := range policy.Rules {
		if rule.Action != "allow" || rule.From != source || rule.To != target || !protocolAllowed(rule.Protocol, protocol) {
			continue
		}
		if rule.DestinationCIDR != "" {
			_, network, err := net.ParseCIDR(rule.DestinationCIDR)
			if err != nil || !network.Contains(net.ParseIP(destinationAddress)) {
				continue
			}
		}
		if rule.SourceCIDR != "" {
			_, network, err := net.ParseCIDR(rule.SourceCIDR)
			if err != nil || !network.Contains(net.ParseIP(sourceAddress)) {
				continue
			}
		}
		if len(rule.Ports) == 0 {
			return true
		}
		for _, value := range rule.Ports {
			if value == strconv.Itoa(port) {
				return true
			}
		}
	}
	return false
}

func protocolAllowed(rule, wanted string) bool {
	return rule == wanted || rule == "tcp/udp" || rule == "any"
}

func mtlsDenied(output string) bool {
	return strings.Contains(output, "http_code=400") || strings.Contains(output, "http_code=401") || strings.Contains(output, "http_code=403")
}

func responseDetail(response probeResponse, err error) string {
	details := make([]string, 0, 3)
	if response.Error != "" {
		details = append(details, response.Error)
	}
	if output := strings.TrimSpace(response.Output); output != "" {
		details = append(details, output)
	}
	if err != nil {
		details = append(details, err.Error())
	}
	return strings.Join(details, "; ")
}

func validateAirVPNNetworkTestSite(s model.Site) error {
	enabled := make(map[string]bool, len(s.Modules))
	for _, module := range s.Modules {
		enabled[module.Name] = module.Enabled
	}
	if !enabled["airvpn"] || !enabled["arr"] {
		return errors.New("--airvpn requires enabled airvpn and arr modules")
	}
	arrConfig, ok := s.ModuleConfig["arr"]
	if !ok || arrConfig.Network != model.ModuleNetworkAirVPN {
		return errors.New("--airvpn requires arr to use the AirVPN network mode")
	}
	arr, ok := findManagedEndpoint(s, "lab-arr-01")
	if !ok || arr.VMID != model.ArrVMID || arr.Address != model.ArrGuestAddress || !arr.SSHManaged || !arr.JumpAllowed {
		return errors.New("--airvpn requires the declared ARR guest management contract")
	}
	airvpn, ok := findManagedEndpoint(s, "lab-airvpn-01")
	if !ok || airvpn.VMID != model.AirVPNGuestVMID || airvpn.Address != model.AirVPNGuestAddress {
		return errors.New("--airvpn requires the declared AirVPN transit guest")
	}
	return nil
}

const (
	arrAirVPNPublicProbeCommand  = "/usr/bin/curl --ipv4 --fail --silent --show-error --connect-timeout 5 --max-time 15 --proto '=https' " + airVPNProbeURL
	arrProxmoxDeniedProbeCommand = "/usr/bin/curl --ipv4 --fail --silent --show-error --connect-timeout 3 --max-time 5 telnet://" + model.ProxmoxManagementAddress + ":22 >/dev/null"
)

// runAirVPNNetworkProbe exercises the selected ARR source rather than a
// generic SERVERS probe. It uses the normal restricted SSH route to the
// declared guest and the scoped Proxmox API only to stop and restore its one
// declared transit LXC. No generic guest command execution is available.
func runAirVPNNetworkProbe(ctx context.Context, client *proxmox.Client, node, siteDir string, s model.Site, report *networktest.Report) (runErr error) {
	if client == nil || node == "" || report == nil {
		return errors.New("AirVPN network probe requires a Proxmox client, node, and report")
	}
	if err := validateAirVPNNetworkTestSite(s); err != nil {
		return err
	}
	arr, _ := findManagedEndpoint(s, "lab-arr-01")
	airvpn, _ := findManagedEndpoint(s, "lab-airvpn-01")
	configPath, cleanupConfig, err := temporarySSHConfig(s, siteDir)
	if err != nil {
		return fmt.Errorf("prepare ARR AirVPN probe SSH configuration: %w", err)
	}
	defer cleanupConfig()
	runner := proxmox.SSHRunner{
		ConfigFile: configPath, KnownHosts: deploymentKnownHosts(siteDir), StrictHostKey: "yes",
		HostAlias: arr.Name, IdentityFile: operatorIdentityFile(s),
	}.FreshConnection()

	add := func(name, target, detail string, passed bool) {
		status := "PASS"
		if !passed {
			status = "FAIL"
		}
		now := time.Now().UTC().Format(time.RFC3339)
		report.Results = append(report.Results, networktest.Result{Name: name, Kind: "airvpn", Source: arr.Name, Target: target, Status: status, Detail: detail, Started: now, Finished: now})
	}
	probePublic := func() (string, string, error) {
		return waitForAirVPNPublicEgress(ctx, runner, arr)
	}

	publicIP, detail, err := probePublic()
	add("airvpn/arr/public-egress", airVPNProbeURL, detail, err == nil)
	if err != nil {
		return fmt.Errorf("ARR AirVPN public egress: %w", err)
	}
	if publicIP == "" {
		return errors.New("ARR AirVPN public egress did not return an address")
	}

	deniedOutput, deniedErr := runner.Run(ctx, arr.Address, model.DefaultAdminSSHUser, arrProxmoxDeniedProbeCommand)
	add("airvpn/arr/proxmox-denied", model.ProxmoxManagementAddress+":22", strings.TrimSpace(string(deniedOutput)), deniedErr != nil)
	if deniedErr == nil {
		return errors.New("ARR unexpectedly reached the Proxmox management SSH port")
	}

	status, err := client.LXCStatus(ctx, node, airvpn.VMID)
	if err != nil {
		return fmt.Errorf("inspect AirVPN transit status: %w", err)
	}
	if status != "running" {
		return fmt.Errorf("AirVPN transit LXC is %s, expected running before fail-closed probe", status)
	}
	stopped := false
	defer func() {
		if !stopped {
			return
		}
		recoveryStarted := time.Now().UTC().Format(time.RFC3339)
		recoveryCtx, cancelRecovery := context.WithTimeout(context.Background(), networkTestCleanupTimeout)
		recoveryErr := client.StartLXC(recoveryCtx, node, airvpn.VMID)
		if recoveryErr == nil {
			recoveryErr = waitForLXCStatus(recoveryCtx, client, node, airvpn.VMID, "running")
		}
		cancelRecovery()
		status := "PASS"
		if recoveryErr != nil {
			status = "FAIL"
		}
		report.Results = append(report.Results, networktest.Result{Name: "airvpn/arr/router-recovery", Kind: "airvpn", Source: arr.Name, Target: airvpn.Name, Status: status, Detail: compactError(recoveryErr), Started: recoveryStarted, Finished: time.Now().UTC().Format(time.RFC3339)})
		if recoveryErr != nil {
			if runErr == nil {
				runErr = fmt.Errorf("restore AirVPN transit after probe: %w", recoveryErr)
			} else {
				runErr = fmt.Errorf("%w; restore AirVPN transit after probe: %v", runErr, recoveryErr)
			}
		}
	}()

	if err := client.StopLXC(ctx, node, airvpn.VMID); err != nil {
		return fmt.Errorf("stop exact AirVPN transit LXC: %w", err)
	}
	stopped = true
	if err := waitForLXCStatus(ctx, client, node, airvpn.VMID, "stopped"); err != nil {
		return fmt.Errorf("wait for AirVPN transit LXC to stop: %w", err)
	}
	downOutput, downErr := runner.Run(ctx, arr.Address, model.DefaultAdminSSHUser, arrAirVPNPublicProbeCommand)
	add("airvpn/arr/tunnel-down-denied", airVPNProbeURL, strings.TrimSpace(string(downOutput)), downErr != nil)
	if downErr == nil {
		return errors.New("ARR retained public egress while the AirVPN transit LXC was stopped")
	}

	if err := client.StartLXC(ctx, node, airvpn.VMID); err != nil {
		return fmt.Errorf("restart exact AirVPN transit LXC: %w", err)
	}
	if err := waitForLXCStatus(ctx, client, node, airvpn.VMID, "running"); err != nil {
		return fmt.Errorf("wait for AirVPN transit LXC to restart: %w", err)
	}
	stopped = false
	recoveredIP, recoveredDetail, recoveredErr := probePublic()
	add("airvpn/arr/router-recovery", airvpn.Name, recoveredDetail, recoveredErr == nil && recoveredIP != "")
	if recoveredErr != nil {
		return fmt.Errorf("ARR AirVPN egress after transit restart: %w", recoveredErr)
	}
	return nil
}

func waitForAirVPNPublicEgress(ctx context.Context, runner proxmox.SSHRunner, arr model.Component) (string, string, error) {
	var lastDetail string
	for attempt := 0; attempt < airVPNProbeAttempts; attempt++ {
		output, err := runner.Run(ctx, arr.Address, model.DefaultAdminSSHUser, arrAirVPNPublicProbeCommand)
		if err == nil {
			address, parseErr := parsePublicIPv4(string(output))
			if parseErr == nil {
				return address, address, nil
			}
			lastDetail = parseErr.Error()
		} else {
			lastDetail = strings.TrimSpace(string(output))
			if lastDetail == "" {
				lastDetail = compactError(err)
			}
		}
		if attempt == airVPNProbeAttempts-1 {
			break
		}
		timer := time.NewTimer(airVPNProbeInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", lastDetail, ctx.Err()
		case <-timer.C:
		}
	}
	if lastDetail == "" {
		lastDetail = "no public IPv4 response"
	}
	return "", lastDetail, errors.New("ARR did not establish AirVPN public egress")
}

func parsePublicIPv4(output string) (string, error) {
	fields := strings.Fields(output)
	if len(fields) != 1 {
		return "", errors.New("public egress probe did not return one IPv4 address")
	}
	ip := net.ParseIP(fields[0])
	if ip == nil || ip.To4() == nil {
		return "", errors.New("public egress probe did not return an IPv4 address")
	}
	ip = ip.To4()
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
		return "", errors.New("public egress probe returned a non-public IPv4 address")
	}
	return ip.String(), nil
}

func waitForLXCStatus(ctx context.Context, client *proxmox.Client, node string, vmid int, wanted string) error {
	var lastStatus string
	for attempt := 0; attempt < airVPNProbeAttempts; attempt++ {
		status, err := client.LXCStatus(ctx, node, vmid)
		if err != nil {
			return err
		}
		lastStatus = status
		if status == wanted {
			return nil
		}
		if attempt == airVPNProbeAttempts-1 {
			break
		}
		timer := time.NewTimer(airVPNProbeInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return fmt.Errorf("LXC %d remained %s, expected %s", vmid, lastStatus, wanted)
}

func networkTestOverall(results []networktest.Result, cleanupErr error) string {
	if cleanupErr != nil {
		return "HOLD"
	}
	for _, result := range results {
		if result.Status == "HOLD" {
			return "HOLD"
		}
		if result.Status == "FAIL" {
			return "FAIL"
		}
	}
	for _, result := range results {
		if result.Status == "INCONCLUSIVE" {
			return "INCONCLUSIVE"
		}
	}
	return "PASS"
}

func writeNetworkTestReport(s model.Site, report networktest.Report) error {
	directory := filepath.Join(site.RuntimeDir(s), "network-tests", report.RunID)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	digest := sha256.Sum256(data)
	if err := writePrivate(filepath.Join(directory, "report.json"), data); err != nil {
		return err
	}
	return writePrivate(filepath.Join(directory, "report.sha256"), []byte(hex.EncodeToString(digest[:])+"  report.json\n"))
}

type networkTestProgress struct {
	out     io.Writer
	total   int
	current int
	active  bool
	started time.Time
}

func newNetworkTestProgress(out io.Writer, total int) *networkTestProgress {
	return &networkTestProgress{out: out, total: total}
}

func (p *networkTestProgress) start(name string) {
	p.current++
	p.active = true
	p.started = time.Now()
	fmt.Fprintf(p.out, "[%d/%d] %s\n", p.current, p.total, name)
}

func (p *networkTestProgress) complete() {
	if !p.active {
		return
	}
	p.active = false
	fmt.Fprintf(p.out, "      PASS (%s)\n", formatOperationDuration(time.Since(p.started)))
}

func (p *networkTestProgress) fail(err error) {
	if !p.active {
		return
	}
	p.active = false
	fmt.Fprintf(p.out, "      FAIL: %s\n", compactNetworkTestDetail(compactError(err)))
}

func operatorNetworkTestStatus(status string) string {
	if status == "PASS" {
		return "PASS"
	}
	return "FAIL"
}

func compactNetworkTestDetail(detail string) string {
	detail = strings.TrimSpace(detail)
	for _, prefix := range []string{"HOLD: ", "INCONCLUSIVE: ", "FAIL: "} {
		detail = strings.TrimPrefix(detail, prefix)
	}
	detail = strings.Join(strings.Fields(detail), " ")
	const maxDetailLength = 240
	if len(detail) > maxDetailLength {
		return detail[:maxDetailLength-3] + "..."
	}
	return detail
}

type networkTestOperatorError struct{ cause error }

func (e networkTestOperatorError) Error() string {
	detail := compactNetworkTestDetail(e.cause.Error())
	if detail == "" {
		detail = "review the failed cases and correct the reported path or cleanup problem before retrying"
	}
	return "network test failed: " + detail
}

func (e networkTestOperatorError) Unwrap() error { return e.cause }

func finishNetworkTest(out io.Writer, jsonOutput bool, report networktest.Report, runErr error) error {
	if runErr == nil && report.Overall != "PASS" {
		runErr = errors.New("network test did not pass; review the failed cases and correct the reported path or cleanup problem before retrying")
	}
	if jsonOutput {
		data, _ := json.MarshalIndent(report, "", "  ")
		fmt.Fprintln(out, string(data))
	} else {
		fmt.Fprintf(out, "Network test %s: %s (%d cases)\n", report.RunID, operatorNetworkTestStatus(report.Overall), len(report.Results))
		for _, result := range report.Results {
			status := operatorNetworkTestStatus(result.Status)
			fmt.Fprintf(out, "  %-12s %s\n", status, result.Name)
			if status == "FAIL" {
				if detail := compactNetworkTestDetail(result.Detail); detail != "" {
					fmt.Fprintf(out, "      %s\n", detail)
				}
			}
		}
		cleanupStatus := operatorNetworkTestStatus(report.Cleanup)
		fmt.Fprintf(out, "Cleanup: %s\n", cleanupStatus)
		if cleanupStatus == "FAIL" {
			if detail := compactNetworkTestDetail(report.Cleanup); detail != "" {
				fmt.Fprintf(out, "      %s\n", detail)
			}
		}
		if runErr != nil {
			fmt.Fprintf(out, "Reason: %s\n", compactNetworkTestDetail(runErr.Error()))
		}
		fmt.Fprintf(out, "Evidence: %s\n", report.EvidencePath)
	}
	if runErr != nil {
		return networkTestOperatorError{cause: runErr}
	}
	return nil
}

func cleanupNetworkProbes(ctx context.Context, client *proxmox.Client, node string, s model.Site, probes []networktest.Probe) error {
	ids := make([]int, 0, networktest.VMIDMax-networktest.VMIDMin+1)
	if len(probes) == 0 {
		for id := networktest.VMIDMin; id <= networktest.VMIDMax; id++ {
			ids = append(ids, id)
		}
	} else {
		for _, probe := range probes {
			ids = append(ids, probe.VMID)
		}
	}
	for _, id := range ids {
		kind, current, err := client.GuestConfig(ctx, node, id)
		if err != nil {
			if proxmox.IsNotFound(err) {
				continue
			}
			return fmt.Errorf("inspect reserved VMID %d: %w", id, err)
		}
		tags, _ := current["tags"].(string)
		description, _ := current["description"].(string)
		if kind != proxmox.KindLXC || !hasExactProxmoxTag(tags, networktest.HarnessTag) || !hasExactDescriptionField(description, "installation", s.SecretMetadata.InstallationID) {
			return fmt.Errorf("reserved VMID %d is occupied by an unknown guest", id)
		}
		status, statusErr := client.LXCStatus(ctx, node, id)
		if statusErr != nil && !proxmox.IsNotFound(statusErr) {
			return fmt.Errorf("inspect owned network probe %d status: %w", id, statusErr)
		}
		if statusErr == nil && status == "running" {
			if err := client.StopLXC(ctx, node, id); err != nil {
				return fmt.Errorf("stop owned network probe %d: %w", id, err)
			}
		}
		if err := client.DestroyLXC(ctx, node, id); err != nil {
			return fmt.Errorf("destroy owned network probe %d: %w", id, err)
		}
		if _, _, err := client.GuestConfig(ctx, node, id); err == nil || !proxmox.IsNotFound(err) {
			return fmt.Errorf("verify cleanup of network probe %d", id)
		}
	}
	return nil
}

func hasExactProxmoxTag(tags, wanted string) bool {
	for _, tag := range strings.Split(tags, ";") {
		if strings.TrimSpace(tag) == wanted {
			return true
		}
	}
	return false
}

func hasExactDescriptionField(description, key, wanted string) bool {
	want := key + "=" + wanted
	for _, field := range strings.Fields(description) {
		if field == want {
			return true
		}
	}
	return false
}

func mapToValues(values map[string]string) (result url.Values) {
	result = url.Values{}
	for key, value := range values {
		result.Set(key, value)
	}
	return result
}
