package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/firewall"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/site"
)

func runFirewall(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher firewall status|show|diff|counters|logs|verify")
	}
	command := args[0]
	if command == "rule" {
		return runFirewallRules(args[1:], out)
	}
	fs := flag.NewFlagSet("firewall "+command, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	live := fs.Bool("live", false, "inspect the managed gateway over the generated SSH path")
	jsonOutput := fs.Bool("json", false, "write JSON output")
	format := fs.String("format", "human", "show format: human or nft")
	zone := fs.String("zone", "", "restrict logs to a zone name")
	limit := fs.Int("limit", 50, "maximum log lines")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	plan, err := firewall.PlanFromSite(s)
	if err != nil {
		return err
	}
	switch command {
	case "status":
		return firewallStatus(*siteDir, s, plan, *live, *jsonOutput, out)
	case "show":
		return firewallShow(s, plan, *format, *jsonOutput, out)
	case "diff":
		return firewallDiff(*siteDir, s, plan, *ageIdentity, *live, *jsonOutput, out)
	case "counters":
		return firewallCounters(*siteDir, s, *live, *jsonOutput, out)
	case "logs":
		zoneName := "all"
		if *zone != "" {
			zoneName = strings.ToUpper(*zone)
		}
		if *limit < 1 || *limit > 1000 {
			return errors.New("--limit must be between 1 and 1000")
		}
		return firewallLiveRead(*siteDir, s, []string{"sudo", "/usr/lib/boetticher/inspect-firewall", "kernel-logs", fmt.Sprint(*limit), zoneName}, *live, false, out, "Kernel log entries for boetticher firewall drops.")
	case "verify":
		return firewallVerify(*siteDir, s, plan, *ageIdentity, *live, *jsonOutput, out)
	default:
		return fmt.Errorf("unknown firewall command %q", command)
	}
}

func firewallStatus(siteDir string, s model.Site, plan firewall.Plan, live, jsonOutput bool, out io.Writer) error {
	status := map[string]any{"mode": plan.Mode, "engine": plan.Engine, "model_revision": plan.ModelRevision, "ipv4_only": plan.IPv4Only, "forwarding_after_policy": plan.Forwarding, "interfaces": plan.Interfaces, "status": "PASS", "detail": "generated firewall contract and module network intents are valid"}
	if err := firewall.ValidateNetworkIntentCoverage(s, plan); err != nil {
		status["status"] = "FAIL"
		status["reason"] = err.Error()
		status["next_action"] = "Correct the generated network policy before deployment"
		if jsonOutput {
			_ = writeCLIJSON(out, status)
		}
		return fmt.Errorf("firewall network contract failed: %w", err)
	}
	var liveErr error
	if live && s.Gateway.Mode == model.GatewayModeManaged {
		data, err := gatewayCommand(siteDir, s, "sudo", gatewayStatusScript, "status")
		if err != nil {
			return err
		}
		liveStatus, parseErr := parseGatewayStatus(string(data))
		if parseErr != nil {
			return parseErr
		}
		if err := firewall.ValidateUpstreamObservation(plan, liveStatus.Upstream); err != nil {
			return fmt.Errorf("managed gateway upstream DHCP is not safe: %w", err)
		}
		if liveErr = validateManagedGatewayServices(liveStatus); liveErr != nil {
			status["status"] = "FAIL"
			status["reason"] = liveErr.Error()
			status["next_action"] = "Restore the named managed-gateway service and rerun firewall status --live"
		}
		status["live"] = liveStatus
	} else if live {
		status["live"] = "external firewall state is outside boetticher"
	}
	if jsonOutput {
		if err := writeCLIJSON(out, status); err != nil {
			return err
		}
		if liveErr != nil {
			return fmt.Errorf("firewall status failed: %w", liveErr)
		}
		return nil
	}
	fmt.Fprintln(out, "Firewall")
	fmt.Fprintf(out, "  Mode        %s\n  Engine      %s\n  Model       %s\n", plan.Mode, plan.Engine, plan.ModelRevision)
	if s.Gateway.Mode == model.GatewayModeExternal {
		fmt.Fprintln(out, "  Result      PASS external firewall contract generated")
		fmt.Fprintln(out, "  Management  outside boetticher")
		fmt.Fprintln(out, "  Trunk       VLANs 5, 10, 20, 30, 40, 99")
		return nil
	}
	if live {
		liveStatus := status["live"].(gatewayLiveStatus)
		forwarding := "disabled"
		if liveStatus.Forwarding == "1" {
			forwarding = "enabled"
		}
		fmt.Fprintf(out, "  Forwarding  %s\n  Ruleset     queried\n", forwarding)
		fmt.Fprintf(out, "  Upstream    PASS DHCP MAC=%s address=%s gateway=%s\n", liveStatus.Upstream.MAC, liveStatus.Upstream.Address, liveStatus.Upstream.Gateway)
		for _, publication := range plan.Publications {
			fmt.Fprintf(out, "  Published   PASS %s %s:%d/%s -> %s\n", strings.ToUpper(publication.Service), strings.Split(liveStatus.Upstream.Address, "/")[0], publication.Port, publication.Protocol, publication.Destination)
		}
	} else {
		fmt.Fprintf(out, "  Forwarding  enabled after policy deployment\n  Ruleset     generated\n")
		fmt.Fprintln(out, "  Result      PASS generated firewall contract available")
		fmt.Fprintln(out, "  Upstream    use --live to query DHCP lease/address")
		for _, publication := range plan.Publications {
			fmt.Fprintf(out, "  Published   use --live to verify %s :%d/%s -> %s\n", strings.ToUpper(publication.Service), publication.Port, publication.Protocol, publication.Destination)
		}
	}
	fmt.Fprintln(out, "Interfaces")
	for _, iface := range plan.Interfaces {
		address := iface.Address
		if iface.Method == "dhcp" {
			address = "upstream DHCP"
		}
		if live {
			liveStatus := status["live"].(gatewayLiveStatus)
			if observed := liveStatus.Interfaces[iface.Name]; observed != "" {
				address = observed
			}
		}
		fmt.Fprintf(out, "  %-9s %-10s %s\n", iface.Role, iface.Name, address)
	}
	if live {
		liveStatus := status["live"].(gatewayLiveStatus)
		fmt.Fprintln(out, "Services")
		for _, service := range []string{"nftables", "kea-dhcp4-server", "kea-dhcp-ddns-server", "dnsmasq"} {
			fmt.Fprintf(out, "  %-18s %s\n", service, humanServiceResult(liveStatus.Services[service]))
		}
	}
	if live {
		if liveErr == nil {
			fmt.Fprintln(out, "Live state    PASS (managed gateway queried)")
		} else {
			fmt.Fprintf(out, "Live state    FAIL %s\n", status["reason"])
			return fmt.Errorf("firewall status failed: %w", liveErr)
		}
	} else {
		fmt.Fprintln(out, "Live state    use --live to compare managed gateway state")
	}
	return nil
}

func humanServiceResult(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), "active") {
		return "PASS"
	}
	return "FAIL"
}

func validateManagedGatewayServices(liveStatus gatewayLiveStatus) error {
	for _, service := range []string{"nftables", "kea-dhcp4-server", "kea-dhcp-ddns-server", "dnsmasq"} {
		state, ok := liveStatus.Services[service]
		if !ok || strings.TrimSpace(state) == "" {
			return fmt.Errorf("managed gateway service %s state is missing", service)
		}
		if !strings.EqualFold(strings.TrimSpace(state), "active") {
			return fmt.Errorf("managed gateway service %s is %q, expected active", service, state)
		}
	}
	return nil
}

const gatewayStatusScript = "/usr/lib/boetticher/inspect-firewall"

type gatewayLiveStatus struct {
	Forwarding string                       `json:"forwarding"`
	Services   map[string]string            `json:"services"`
	Interfaces map[string]string            `json:"interfaces"`
	Upstream   firewall.UpstreamObservation `json:"upstream"`
}

func parseGatewayStatus(output string) (gatewayLiveStatus, error) {
	status := gatewayLiveStatus{Services: map[string]string{}, Interfaces: map[string]string{}}
	seenKeys := map[string]struct{}{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || value == "" {
			return gatewayLiveStatus{}, fmt.Errorf("managed gateway status contains malformed line %q", line)
		}
		if _, exists := seenKeys[key]; exists {
			return gatewayLiveStatus{}, fmt.Errorf("managed gateway status contains duplicate field %q", key)
		}
		seenKeys[key] = struct{}{}
		switch {
		case key == "forwarding":
			status.Forwarding = value
		case strings.HasPrefix(key, "service."):
			status.Services[strings.TrimPrefix(key, "service.")] = value
		case strings.HasPrefix(key, "iface."):
			status.Interfaces[strings.TrimPrefix(key, "iface.")] = value
		case key == "upstream.interface":
			status.Upstream.Interface = value
		case key == "upstream.mac":
			status.Upstream.MAC = value
		case key == "upstream.address":
			status.Upstream.Address = value
		case key == "upstream.gateway":
			status.Upstream.Gateway = value
		default:
			return gatewayLiveStatus{}, fmt.Errorf("managed gateway status contains unknown field %q", key)
		}
	}
	if status.Forwarding == "" || len(status.Services) != 4 || len(status.Interfaces) != 7 || status.Upstream.Interface == "" || status.Upstream.MAC == "" || status.Upstream.Address == "" || status.Upstream.Gateway == "" {
		return gatewayLiveStatus{}, errors.New("managed gateway status is incomplete")
	}
	return status, nil
}

func firewallShow(s model.Site, plan firewall.Plan, format string, jsonOutput bool, out io.Writer) error {
	if format != "human" && format != "nft" {
		return errors.New("--format must be human or nft")
	}
	if format == "nft" {
		if s.Gateway.Mode != model.GatewayModeManaged {
			return errors.New("nftables output is unavailable in external gateway mode")
		}
		ruleset, err := renderDeploymentNFT(plan)
		if err != nil {
			return err
		}
		_, err = out.Write([]byte(ruleset))
		return err
	}
	if s.Gateway.Mode == model.GatewayModeExternal {
		contract, err := firewall.RenderExternalContract(s, plan)
		if err != nil {
			return err
		}
		if jsonOutput {
			return writeCLIJSON(out, map[string]any{"mode": plan.Mode, "model_revision": plan.ModelRevision, "contract": contract})
		}
		_, err = out.Write([]byte(contract))
		return err
	}
	if jsonOutput {
		return writeCLIJSON(out, plan)
	}
	fmt.Fprintf(out, "Firewall policy (model %s)\n", plan.ModelRevision)
	for _, rule := range plan.Rules {
		ports := ""
		if len(rule.Ports) != 0 {
			ports = " " + strings.Join(rule.Ports, ",")
		}
		fmt.Fprintf(out, "  %-7s %-10s -> %-10s %s%s\n", rule.Action, rule.From, rule.To, rule.Protocol, ports)
	}
	return nil
}

func firewallDiff(siteDir string, s model.Site, plan firewall.Plan, ageIdentity string, live, jsonOutput bool, out io.Writer) error {
	if err := firewall.ValidateNetworkIntentCoverage(s, plan); err != nil {
		if !jsonOutput {
			fmt.Fprintf(out, "Firewall diff: FAIL %v\n", err)
		}
		return fmt.Errorf("firewall network contract failed: %w", err)
	}
	if s.Gateway.Mode == model.GatewayModeExternal {
		if jsonOutput {
			return writeCLIJSON(out, map[string]string{"mode": "external", "status": "PASS", "detail": "external firewall contract generated; enforcement is outside boetticher management"})
		}
		fmt.Fprintln(out, "External firewall contract: PASS generated; enforcement is outside boetticher. Use firewall show for the contract.")
		return nil
	}
	var err error
	if live {
		data, commandErr := gatewayCommand(siteDir, s, "sudo", gatewayStatusScript, "status")
		if commandErr != nil {
			return commandErr
		}
		liveStatus, parseErr := parseGatewayStatus(string(data))
		if parseErr != nil {
			return parseErr
		}
		plan, err = planFromLiveUpstream(siteDir, s, ageIdentity, liveStatus.Upstream)
		if err != nil {
			return err
		}
	}
	ruleset, err := renderDeploymentNFT(plan)
	if err != nil {
		return err
	}
	if err := firewall.ValidateNFT(ruleset); err != nil {
		return err
	}
	if !jsonOutput {
		fmt.Fprintln(out, "Firewall diff: PASS generated policy is valid")
	}
	result := map[string]any{"model_revision": plan.ModelRevision, "desired": true, "live_checked": live, "status": "NOT TESTED", "detail": "live boetticher-owned nftables state was not queried"}
	if live {
		data, commandErr := gatewayCommand(siteDir, s, "sudo", "/usr/lib/boetticher/inspect-firewall", "ruleset")
		if commandErr != nil {
			return commandErr
		}
		diff, compareErr := firewall.CompareNFT(plan, data)
		if compareErr != nil {
			return compareErr
		}
		result["diff"] = diff
		if diff.Current() {
			result["status"] = "PASS"
			result["detail"] = "boetticher-owned tables, chains, and tagged rules match the current model"
		} else {
			result["status"] = "DRIFT"
			result["detail"] = "boetticher-owned nftables state differs from the current model"
		}
	}
	if jsonOutput {
		return writeCLIJSON(out, result)
	}
	if live {
		if result["status"] == "PASS" {
			fmt.Fprintf(out, "Firewall rules match the current boetticher model (model %s).\n", plan.ModelRevision)
		} else {
			fmt.Fprintf(out, "Firewall diff: FAIL rules differ from the current boetticher model (model %s).\n", plan.ModelRevision)
			printNFTDiff(out, result["diff"].(firewall.NFTDiff))
		}
	} else {
		fmt.Fprintf(out, "Firewall rules are configured in the current model projection (model %s).\n", plan.ModelRevision)
		fmt.Fprintln(out, "Live comparison: run with --live to compare boetticher-owned nftables tables and rules.")
	}
	if live && result["status"] != "PASS" {
		return errors.New("firewall diff failed: installed rules differ from the current model; correct the drift and rerun")
	}
	return nil
}

func printNFTDiff(out io.Writer, diff firewall.NFTDiff) {
	for _, item := range diff.MissingTables {
		fmt.Fprintf(out, "  missing table  %s\n", item)
	}
	for _, item := range diff.MissingChains {
		fmt.Fprintf(out, "  missing chain  %s\n", item)
	}
	for _, item := range diff.MissingRules {
		fmt.Fprintf(out, "  missing rule   %s\n", item)
	}
	for _, item := range diff.UnexpectedRules {
		fmt.Fprintf(out, "  unexpected rule %s\n", item)
	}
	for _, item := range diff.SemanticDrift {
		fmt.Fprintf(out, "  semantic drift %s\n", item)
	}
}

func firewallCounters(siteDir string, s model.Site, live, jsonOutput bool, out io.Writer) error {
	if s.Gateway.Mode == model.GatewayModeExternal {
		if jsonOutput {
			_ = writeCLIJSON(out, map[string]string{"status": "FAIL", "reason": "firewall counters belong to the operator-managed external appliance", "next_action": "Inspect counters using the external firewall interface"})
		} else {
			fmt.Fprintln(out, "Firewall counters: FAIL live counters are outside boetticher management; inspect the external firewall")
		}
		return errors.New("firewall counters failed: external firewall counters are not inspectable by boetticher")
	}
	if !live {
		if jsonOutput {
			_ = writeCLIJSON(out, map[string]string{"status": "FAIL", "reason": "live nftables counters were not requested", "next_action": "Run boetticher firewall counters --live"})
		} else {
			fmt.Fprintln(out, "Firewall counters: FAIL live nftables counters were not requested; run boetticher firewall counters --live")
		}
		return errors.New("firewall counters failed: --live is required")
	}
	data, err := gatewayCommand(siteDir, s, "sudo", "/usr/lib/boetticher/inspect-firewall", "ruleset")
	if err != nil {
		return err
	}
	counters, err := firewall.ParseCounters(data)
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeCLIJSON(out, map[string]any{"model_revision": mustRevision(s), "counters": counters})
	}
	if len(counters) == 0 {
		fmt.Fprintln(out, "Firewall counters: no named boetticher counters returned")
		return nil
	}
	fmt.Fprintln(out, "Firewall counters")
	fmt.Fprintf(out, "  %-46s %12s %12s\n", "Rule", "Packets", "Bytes")
	for _, counter := range counters {
		fmt.Fprintf(out, "  %-46s %12d %12d\n", strings.TrimPrefix(counter.Rule, "boetticher:"), counter.Packets, counter.Bytes)
	}
	return nil
}

func firewallVerify(siteDir string, s model.Site, plan firewall.Plan, ageIdentity string, live, jsonOutput bool, out io.Writer) error {
	results := map[string]string{}
	if err := firewall.ValidateNetworkIntentCoverage(s, plan); err != nil {
		if !jsonOutput {
			fmt.Fprintf(out, "Firewall verification: FAIL %v\n", err)
		}
		return fmt.Errorf("firewall network contract failed: %w", err)
	}
	if s.Gateway.Mode == model.GatewayModeManaged {
		if live {
			data, commandErr := gatewayCommand(siteDir, s, "sudo", gatewayStatusScript, "status")
			if commandErr != nil {
				return commandErr
			}
			liveStatus, parseErr := parseGatewayStatus(string(data))
			if parseErr != nil {
				return parseErr
			}
			var planErr error
			plan, planErr = planFromLiveUpstream(siteDir, s, ageIdentity, liveStatus.Upstream)
			if planErr != nil {
				return planErr
			}
		}
		ruleset, err := renderDeploymentNFT(plan)
		if err != nil {
			return err
		}
		if err := firewall.ValidateNFT(ruleset); err != nil {
			return err
		}
		results["ruleset"] = "PASS"
		results["nat"] = "PASS"
		results["ipv4_only"] = "PASS"
		if live {
			data, err := gatewayCommand(siteDir, s, "sudo", "/usr/lib/boetticher/inspect-firewall", "ruleset")
			if err != nil {
				return err
			}
			diff, err := firewall.CompareNFT(plan, data)
			if err != nil {
				return err
			}
			if !diff.Current() {
				return fmt.Errorf("live firewall ruleset drift: %+v", diff)
			}
			results["live_ruleset"] = "PASS"
		} else {
			results["live_ruleset"] = "NOT TESTED"
		}
	} else {
		results["contract"] = "PASS"
		results["external_policy"] = "outside boetticher management"
		results["observable_paths"] = "NOT TESTED"
	}
	if jsonOutput {
		return writeCLIJSON(out, results)
	}
	fmt.Fprintln(out, "Firewall verification")
	for key, value := range results {
		if value == "NOT TESTED" {
			continue
		}
		fmt.Fprintf(out, "  %-20s %s\n", key, value)
	}
	return nil
}

func firewallLiveRead(siteDir string, s model.Site, command []string, live, jsonOutput bool, out io.Writer, detail string) error {
	if s.Gateway.Mode == model.GatewayModeExternal {
		if jsonOutput {
			_ = writeCLIJSON(out, map[string]string{"status": "FAIL", "reason": "live firewall state belongs to the operator-managed external appliance", "next_action": "Use the external firewall interface"})
		} else {
			fmt.Fprintln(out, "Firewall read: FAIL live state belongs to the operator-managed external appliance")
		}
		return errors.New("firewall read failed: external firewall state is not inspectable by boetticher")
	}
	if !live {
		if jsonOutput {
			_ = writeCLIJSON(out, map[string]string{"status": "FAIL", "reason": detail + " was not requested", "next_action": "Repeat the command with --live"})
		} else {
			fmt.Fprintln(out, detail+": FAIL live inspection requires --live; repeat the command with --live")
		}
		return errors.New("firewall read failed: --live is required")
	}
	data, err := gatewayCommand(siteDir, s, command...)
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeCLIJSON(out, map[string]any{"model_revision": mustRevision(s), "output": string(data)})
	}
	_, err = out.Write(data)
	return err
}

func gatewayCommand(siteDir string, s model.Site, command ...string) ([]byte, error) {
	if s.Gateway.Mode != model.GatewayModeManaged {
		return nil, errors.New("live gateway inspection is unavailable in external mode")
	}
	quoted := make([]string, len(command))
	for i, argument := range command {
		quoted[i] = remoteShellQuote(argument)
	}
	component, ok := findManagedEndpoint(s, "lab-fw-01")
	if !ok {
		return nil, errors.New("managed gateway is absent from the desired model")
	}
	configPath, cleanupConfig, err := temporarySSHConfig(s, siteDir)
	if err != nil {
		return nil, fmt.Errorf("prepare SSH configuration: %w", err)
	}
	defer cleanupConfig()
	runner := proxmox.SSHRunner{
		ConfigFile:    configPath,
		KnownHosts:    deploymentKnownHosts(siteDir),
		StrictHostKey: "yes",
		HostAlias:     "firewall",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	output, err := runner.Run(ctx, component.Address, component.SSHUser, strings.Join(quoted, " "))
	if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, errors.New("live gateway inspection timed out")
	}
	return output, err
}

// OpenSSH passes the remote command through the account shell. Quote each
// fixed-helper argument so a CLI filter cannot become shell syntax remotely.
func remoteShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func writeCLIJSON(out io.Writer, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	_, err = out.Write(append(data, '\n'))
	return err
}
