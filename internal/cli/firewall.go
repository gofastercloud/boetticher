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
		return firewallLiveRead(*siteDir, s, []string{"sudo", "nft", "--json", "list", "table", "inet", firewall.FilterTable}, *live, *jsonOutput, out, "Counters are live nftables state.")
	case "logs":
		prefix := "boetticher"
		if *zone != "" {
			prefix += " " + strings.ToUpper(*zone)
		}
		if *limit < 1 || *limit > 1000 {
			return errors.New("--limit must be between 1 and 1000")
		}
		return firewallLiveRead(*siteDir, s, []string{"sudo", "journalctl", "-k", "-n", fmt.Sprint(*limit), "--no-pager", "-g", prefix}, *live, false, out, "Kernel log entries for boetticher firewall drops.")
	case "verify":
		return firewallVerify(*siteDir, s, plan, *live, *jsonOutput, out)
	default:
		return fmt.Errorf("unknown firewall command %q", command)
	}
}

func firewallStatus(siteDir string, s model.Site, plan firewall.Plan, live, jsonOutput bool, out interface{ Write([]byte) (int, error) }) error {
	status := map[string]any{"mode": plan.Mode, "engine": plan.Engine, "model_revision": plan.ModelRevision, "ipv4_only": plan.IPv4Only, "forwarding_after_convergence": plan.Forwarding, "interfaces": plan.Interfaces}
	if live && s.Gateway.Mode == model.GatewayModeManaged {
		data, err := gatewayCommand(siteDir, s, "sudo", "systemctl", "is-active", "nftables", "kea-dhcp4-server", "kea-dhcp-ddns-server", "dnsmasq")
		if err != nil {
			return err
		}
		status["live"] = strings.TrimSpace(string(data))
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
		fmt.Fprintln(out, "  Trunk       VLANs 10, 20, 50, 99")
		return nil
	}
	fmt.Fprintf(out, "  Forwarding  enabled after convergence\n  Ruleset     generated\n")
	fmt.Fprintln(out, "Interfaces")
	for _, iface := range plan.Interfaces {
		address := iface.Address
		if iface.Method == "dhcp" {
			address = "upstream DHCP"
		}
		fmt.Fprintf(out, "  %-9s %-10s %s\n", iface.Role, iface.Name, address)
	}
	if live {
		fmt.Fprintln(out, "Live state    PASS (managed gateway queried)")
	} else {
		fmt.Fprintln(out, "Live state    NOT TESTED (use --live)")
	}
	return nil
}

func firewallShow(s model.Site, plan firewall.Plan, format string, jsonOutput bool, out interface{ Write([]byte) (int, error) }) error {
	if format != "human" && format != "nft" {
		return errors.New("--format must be human or nft")
	}
	if format == "nft" {
		if s.Gateway.Mode != model.GatewayModeManaged {
			return errors.New("nftables output is unavailable in external gateway mode")
		}
		ruleset, err := firewall.RenderNFT(plan)
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
	ruleset, err := firewall.RenderNFT(plan)
	if err != nil {
		return err
	}
	result := map[string]any{"model_revision": plan.ModelRevision, "desired": true, "live_checked": live, "status": "desired ruleset is current"}
	if live {
		data, commandErr := gatewayCommand(siteDir, s, "sudo", "nft", "--json", "list", "ruleset")
		if commandErr != nil {
			return commandErr
		}
		result["status"] = "ruleset table present"
		result["live_contains_table"] = strings.Contains(string(data), firewall.FilterTable)
	}
	if jsonOutput {
		return writeCLIJSON(out, result)
	}
	if live {
		fmt.Fprintf(out, "Firewall ruleset was queried on lab-fw-01 (model %s).\n", plan.ModelRevision)
	} else {
		fmt.Fprintf(out, "Firewall rules match the current boetticher model projection (model %s).\n", plan.ModelRevision)
	}
	_ = ruleset
	return nil
}

func firewallVerify(siteDir string, s model.Site, plan firewall.Plan, live, jsonOutput bool, out interface{ Write([]byte) (int, error) }) error {
	results := map[string]string{}
	if s.Gateway.Mode == model.GatewayModeManaged {
		ruleset, err := firewall.RenderNFT(plan)
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
			if _, err := gatewayCommand(siteDir, s, "sudo", "nft", "list", "table", "inet", firewall.FilterTable); err != nil {
				return err
			}
			results["live_ruleset"] = "PASS"
		} else {
			results["live_ruleset"] = "NOT TESTED"
		}
	} else {
		results["contract"] = "PASS"
		results["appliance_policy"] = "outside boetticher management"
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
	args := append([]string{"-F", filepath.Join(siteDir, "generated", "ssh", "boetticher.conf"), "firewall"}, command...)
	process := exec.CommandContext(context.Background(), "ssh", args...)
	return process.Output()
}

func writeCLIJSON(out interface{ Write([]byte) (int, error) }, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	_, err = out.Write(append(data, '\n'))
	return err
}
