package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/site"
)

func runFirewallRules(args []string, out interface{ Write([]byte) (int, error) }) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher firewall rule add|list|remove")
	}
	action := args[0]
	fs := flag.NewFlagSet("firewall rule "+action, flag.ContinueOnError)
	fs.SetOutput(nil)
	siteDir := fs.String("site", ".", "private site repository directory")
	source := fs.String("source", "", "source zone or IPv4/CIDR")
	destination := fs.String("destination", "", "destination zone or IPv4/CIDR")
	vmid := fs.Int("vmid", 0, "resolve a user guest's current unambiguous IPv4 address as destination")
	protocol := fs.String("protocol", "", "tcp, udp, or icmp")
	ports := fs.String("ports", "", "comma-separated ports or ranges")
	id := fs.String("id", "", "stable rule ID (optional; generated when omitted)")
	dryRun := fs.Bool("dry-run", false, "validate and show the change without writing")
	confirm := fs.Bool("confirm", false, "confirm writing the desired firewall rule")
	jsonOutput := fs.Bool("json", false, "write JSON output")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	proxmoxCA := fs.String("proxmox-ca", "", "Proxmox API CA PEM file")
	insecure := fs.Bool("insecure", false, "explicitly allow self-signed Proxmox API TLS")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("firewall rule does not accept positional arguments")
	}
	config, err := site.LoadConfig(*siteDir)
	if err != nil {
		return err
	}
	switch action {
	case "list":
		rules := append([]model.UserFirewallRule(nil), config.UserFirewallRules...)
		sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
		if *jsonOutput {
			return writeCLIJSON(out, rules)
		}
		for _, rule := range rules {
			fmt.Fprintf(out, "%s %s -> %s %s %s\n", rule.ID, rule.Source, rule.Destination, rule.Protocol, strings.Join(rule.Ports, ","))
		}
		return nil
	case "add":
		resolved, _, composeErr := modules.Compose(config)
		if composeErr != nil {
			return composeErr
		}
		if *source == "" || *protocol == "" {
			return errors.New("firewall rule add requires --source and --protocol")
		}
		if (*destination == "") == (*vmid == 0) {
			return errors.New("firewall rule add requires exactly one of --destination or --vmid")
		}
		resolvedDestination := strings.TrimSpace(*destination)
		if *vmid != 0 {
			if *vmid < model.UserGuestIDMin || *vmid > model.UserGuestIDMax {
				return fmt.Errorf("VMID %d is outside the user-workload range", *vmid)
			}
			resolvedDestination, err = resolveFirewallVMID(*siteDir, resolved, *vmid, *ageIdentity, *proxmoxCA, *insecure)
			if err != nil {
				return err
			}
		}
		rule, err := newFirewallRule(*source, resolvedDestination, *protocol, *ports, *id)
		if err != nil {
			return err
		}
		if err := addFirewallRule(*siteDir, config, resolved, rule, *dryRun, *confirm, *jsonOutput, out); err != nil {
			return err
		}
		return nil
	case "remove":
		if *id == "" {
			return errors.New("firewall rule remove requires --id")
		}
		return removeFirewallRule(*siteDir, config, *id, *dryRun, *confirm, *jsonOutput, out)
	default:
		return fmt.Errorf("unknown firewall rule command %q", action)
	}
}

func newFirewallRule(source, destination, protocol, rawPorts, id string) (model.UserFirewallRule, error) {
	ports := []string{}
	if strings.TrimSpace(rawPorts) != "" {
		for _, value := range strings.Split(rawPorts, ",") {
			ports = append(ports, strings.TrimSpace(value))
		}
	}
	rule := model.UserFirewallRule{ID: id, Source: strings.ToUpper(strings.TrimSpace(source)), Destination: strings.TrimSpace(destination), Protocol: strings.ToLower(strings.TrimSpace(protocol)), Ports: ports}
	if rule.ID == "" {
		canonical := rule.Source + "|" + strings.ToUpper(rule.Destination) + "|" + rule.Protocol + "|" + strings.Join(ports, ",")
		digest := sha256.Sum256([]byte(canonical))
		rule.ID = "ufr-" + hex.EncodeToString(digest[:])[:16]
	}
	return rule, nil
}

func addFirewallRule(siteDir string, config model.SiteConfig, resolved model.Site, rule model.UserFirewallRule, dryRun, confirm, jsonOutput bool, out interface{ Write([]byte) (int, error) }) error {
	config.UserFirewallRules = append(config.UserFirewallRules, rule)
	resolved.UserFirewallRules = append(resolved.UserFirewallRules, rule)
	if err := resolved.Validate(); err != nil {
		return err
	}
	if !dryRun && !confirm {
		return errors.New("firewall rule changes require --confirm; use --dry-run to inspect the plan")
	}
	if dryRun {
		if jsonOutput {
			return writeCLIJSON(out, map[string]any{"action": "add", "rule": rule, "status": "DRY-RUN"})
		}
		fmt.Fprintf(out, "Firewall rule would be added: %s\n", rule.ID)
		return nil
	}
	if err := site.SaveConfig(siteDir, config); err != nil {
		return err
	}
	if jsonOutput {
		return writeCLIJSON(out, rule)
	}
	fmt.Fprintf(out, "Firewall rule added: %s\n", rule.ID)
	return nil
}

func removeFirewallRule(siteDir string, config model.SiteConfig, id string, dryRun, confirm, jsonOutput bool, out interface{ Write([]byte) (int, error) }) error {
	index := -1
	for i, rule := range config.UserFirewallRules {
		if rule.ID == id {
			if index != -1 {
				return fmt.Errorf("multiple firewall rules match %s", id)
			}
			index = i
		}
	}
	if index < 0 {
		return fmt.Errorf("no firewall rule matches %s", id)
	}
	removed := config.UserFirewallRules[index]
	config.UserFirewallRules = append(config.UserFirewallRules[:index], config.UserFirewallRules[index+1:]...)
	if !dryRun && !confirm {
		return errors.New("firewall rule changes require --confirm; use --dry-run to inspect the plan")
	}
	if dryRun {
		if jsonOutput {
			return writeCLIJSON(out, map[string]any{"action": "remove", "rule": removed, "status": "DRY-RUN"})
		}
		fmt.Fprintf(out, "Firewall rule would be removed: %s\n", id)
		return nil
	}
	if err := site.SaveConfig(siteDir, config); err != nil {
		return err
	}
	if jsonOutput {
		return writeCLIJSON(out, removed)
	}
	fmt.Fprintf(out, "Firewall rule removed: %s\n", id)
	return nil
}

func resolveFirewallVMID(siteDir string, resolved model.Site, vmid int, ageIdentity, proxmoxCA string, insecure bool) (string, error) {
	client, _, err := loadProxmoxClient(siteDir, resolved, ageIdentity, proxmoxCA, insecure)
	if err != nil {
		return "", fmt.Errorf("resolve VMID %d through Proxmox: %w", vmid, err)
	}
	node, err := client.SingleNode(context.Background())
	if err != nil {
		return "", fmt.Errorf("resolve VMID %d node: %w", vmid, err)
	}
	kind, config, err := client.GuestConfig(context.Background(), node, vmid)
	if err != nil {
		return "", fmt.Errorf("HOLD: read VMID %d guest identity: %w", vmid, err)
	}
	if err := validateGuestIdentity(config, kind, vmid); err != nil {
		return "", fmt.Errorf("HOLD: VMID %d identity: %w", vmid, err)
	}
	addresses := []string{}
	if kind == proxmox.KindQEMU {
		interfaces, agentErr := client.QEMUAgentNetworkInterfaces(context.Background(), node, vmid)
		if agentErr != nil {
			return "", fmt.Errorf("HOLD: read VMID %d current guest addresses: %w", vmid, agentErr)
		}
		for _, iface := range interfaces {
			for _, address := range iface.IPAddresses {
				if ip := net.ParseIP(strings.Split(address.IPAddress, "/")[0]).To4(); ip != nil && ip.IsPrivate() {
					addresses = append(addresses, ip.String())
				}
			}
		}
	} else {
		addresses = addressesFromLXCConfig(config)
	}
	sort.Strings(addresses)
	unique := addresses[:0]
	for _, address := range addresses {
		if len(unique) == 0 || unique[len(unique)-1] != address {
			unique = append(unique, address)
		}
	}
	if len(unique) != 1 {
		return "", fmt.Errorf("HOLD: VMID %d has %d unambiguous relevant IPv4 addresses", vmid, len(unique))
	}
	return unique[0] + "/32", nil
}

func validateGuestIdentity(config map[string]any, kind proxmox.GuestKind, vmid int) error {
	identityKey := "name"
	if kind == proxmox.KindLXC {
		identityKey = "hostname"
	}
	name, ok := config[identityKey].(string)
	if !ok || strings.TrimSpace(name) == "" || strings.ContainsAny(name, "\r\n") {
		return fmt.Errorf("current guest %s identity is missing or invalid", identityKey)
	}
	if value, ok := config["vmid"]; ok {
		number, valid := value.(float64)
		if !valid || int(number) != vmid {
			return errors.New("current guest VMID does not match the selected VMID")
		}
	}
	return nil
}

func addressesFromLXCConfig(config map[string]any) []string {
	var result []string
	for key, value := range config {
		if !strings.HasPrefix(key, "net") {
			continue
		}
		if _, err := strconv.Atoi(strings.TrimPrefix(key, "net")); err != nil {
			continue
		}
		text, ok := value.(string)
		if !ok {
			continue
		}
		for _, field := range strings.Split(text, ",") {
			keyValue := strings.SplitN(strings.TrimSpace(field), "=", 2)
			if len(keyValue) != 2 || keyValue[0] != "ip" {
				continue
			}
			ip, network, err := net.ParseCIDR(keyValue[1])
			if err == nil && ip.To4() != nil && network.IP.To4() != nil && ip.IsPrivate() {
				result = append(result, ip.To4().String())
			}
		}
	}
	return result
}
