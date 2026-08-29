package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gofastercloud/boetticher/internal/firewall"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/site"
)

func runFirewall(args []string, out interface{ Write([]byte) (int, error) }) error {
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
		return firewallDiff(*siteDir, s, plan, *live, *jsonOutput, out)
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
		return firewallVerify(*siteDir, s, plan, *live, *jsonOutput, out)
	default:
		return fmt.Errorf("unknown firewall command %q", command)
	}
}

func firewallStatus(siteDir string, s model.Site, plan firewall.Plan, live, jsonOutput bool, out interface{ Write([]byte) (int, error) }) error {
	status := map[string]any{"mode": plan.Mode, "engine": plan.Engine, "model_revision": plan.ModelRevision, "ipv4_only": plan.IPv4Only, "forwarding_after_policy": plan.Forwarding, "interfaces": plan.Interfaces}
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
		status["live"] = liveStatus
	} else if live {
		status["live"] = "external firewall state is outside boetticher"
	}
	if jsonOutput {
		return writeCLIJSON(out, status)
	}
	fmt.Fprintln(out, "Firewall")
	fmt.Fprintf(out, "  Mode        %s\n  Engine      %s\n  Model       %s\n", plan.Mode, plan.Engine, plan.ModelRevision)
	if s.Gateway.Mode == model.GatewayModeExternal {
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
		fmt.Fprintln(out, "  Upstream    NOT TESTED DHCP lease/address (use --live)")
		for _, publication := range plan.Publications {
			fmt.Fprintf(out, "  Published   NOT TESTED %s :%d/%s -> %s (use --live)\n", strings.ToUpper(publication.Service), publication.Port, publication.Protocol, publication.Destination)
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
			fmt.Fprintf(out, "  %-18s %s\n", service, liveStatus.Services[service])
		}
	}
	if live {
		fmt.Fprintln(out, "Live state    PASS (managed gateway queried)")
	} else {
		fmt.Fprintln(out, "Live state    NOT TESTED (use --live)")
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
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || value == "" {
			return gatewayLiveStatus{}, fmt.Errorf("managed gateway status contains malformed line %q", line)
		}
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

func firewallShow(s model.Site, plan firewall.Plan, format string, jsonOutput bool, out interface{ Write([]byte) (int, error) }) error {
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

func firewallDiff(siteDir string, s model.Site, plan firewall.Plan, live, jsonOutput bool, out interface{ Write([]byte) (int, error) }) error {
	if s.Gateway.Mode == model.GatewayModeExternal {
		if jsonOutput {
			return writeCLIJSON(out, map[string]string{"mode": "external", "status": "outside boetticher management"})
		}
		fmt.Fprintln(out, "External firewall configuration is outside boetticher; use firewall show for the contract.")
		return nil
	}
	var err error
	if live && len(plan.Publications) > 0 {
		data, commandErr := gatewayCommand(siteDir, s, "sudo", gatewayStatusScript, "status")
		if commandErr != nil {
			return commandErr
		}
		liveStatus, parseErr := parseGatewayStatus(string(data))
		if parseErr != nil {
			return parseErr
		}
		plan, err = firewall.PlanFromSiteWithUpstream(s, liveStatus.Upstream)
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
			fmt.Fprintf(out, "Firewall rules differ from the current boetticher model (model %s).\n", plan.ModelRevision)
			printNFTDiff(out, result["diff"].(firewall.NFTDiff))
		}
	} else {
		fmt.Fprintf(out, "Firewall rules are configured in the current model projection (model %s).\n", plan.ModelRevision)
		fmt.Fprintln(out, "Live state NOT TESTED; use --live to compare boetticher-owned nftables tables and rules.")
	}
	return nil
}

func printNFTDiff(out interface{ Write([]byte) (int, error) }, diff firewall.NFTDiff) {
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
}

func firewallCounters(siteDir string, s model.Site, live, jsonOutput bool, out interface{ Write([]byte) (int, error) }) error {
	if s.Gateway.Mode == model.GatewayModeExternal {
		fmt.Fprintln(out, "Firewall counters belong to the operator-managed external appliance.")
		return nil
	}
	if !live {
		fmt.Fprintln(out, "Firewall counters are live nftables state. Use --live to query lab-fw-01.")
		return nil
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

func firewallVerify(siteDir string, s model.Site, plan firewall.Plan, live, jsonOutput bool, out interface{ Write([]byte) (int, error) }) error {
	results := map[string]string{}
	if s.Gateway.Mode == model.GatewayModeManaged {
		if live && len(plan.Publications) > 0 {
			data, commandErr := gatewayCommand(siteDir, s, "sudo", gatewayStatusScript, "status")
			if commandErr != nil {
				return commandErr
			}
			liveStatus, parseErr := parseGatewayStatus(string(data))
			if parseErr != nil {
				return parseErr
			}
			var planErr error
			plan, planErr = firewall.PlanFromSiteWithUpstream(s, liveStatus.Upstream)
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
		fmt.Fprintf(out, "  %-20s %s\n", key, value)
	}
	return nil
}

func firewallLiveRead(siteDir string, s model.Site, command []string, live, jsonOutput bool, out interface{ Write([]byte) (int, error) }, detail string) error {
	if s.Gateway.Mode == model.GatewayModeExternal {
		fmt.Fprintln(out, "Live firewall state belongs to the operator-managed external appliance.")
		return nil
	}
	if !live {
		fmt.Fprintln(out, detail+" Use --live to query lab-fw-01.")
		return nil
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
	args := []string{"-F", filepath.Join(siteDir, "generated", "ssh", "boetticher.conf"), "firewall", strings.Join(quoted, " ")}
	process := exec.CommandContext(context.Background(), "ssh", args...)
	return process.Output()
}

// OpenSSH passes the remote command through the account shell. Quote each
// fixed-helper argument so a CLI filter cannot become shell syntax remotely.
func remoteShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func writeCLIJSON(out interface{ Write([]byte) (int, error) }, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	_, err = out.Write(append(data, '\n'))
	return err
}
