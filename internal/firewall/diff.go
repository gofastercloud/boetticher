package firewall

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
)

// NFTDiff is deliberately limited to the two tables boetticher owns. Other
// nftables tables are operator state and are ignored by comparison.
type NFTDiff struct {
	MissingTables   []string `json:"missing_tables,omitempty"`
	MissingChains   []string `json:"missing_chains,omitempty"`
	MissingRules    []string `json:"missing_rules,omitempty"`
	UnexpectedRules []string `json:"unexpected_rules,omitempty"`
}

func (d NFTDiff) Current() bool {
	return len(d.MissingTables) == 0 && len(d.MissingChains) == 0 && len(d.MissingRules) == 0 && len(d.UnexpectedRules) == 0
}

// CompareNFT compares the JSON emitted by `nft --json list ruleset` with the
// deterministic boetticher projection. Rules are identified by comments in
// the generated tables; this keeps the comparison bounded and avoids parsing
// the whole nftables expression language.
func CompareNFT(plan Plan, live []byte) (NFTDiff, error) {
	if plan.Mode != model.GatewayModeManaged {
		return NFTDiff{}, fmt.Errorf("nftables comparison is only available in managed gateway mode")
	}
	var document struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(live, &document); err != nil {
		return NFTDiff{}, fmt.Errorf("decode nftables JSON: %w", err)
	}
	observedTables := map[string]bool{}
	observedChains := map[string]bool{}
	observedRules := map[string]bool{}
	for _, object := range document.NFTables {
		if raw, ok := object["table"]; ok {
			var table struct {
				Family string `json:"family"`
				Name   string `json:"name"`
			}
			if err := json.Unmarshal(raw, &table); err != nil {
				return NFTDiff{}, fmt.Errorf("decode nftables table: %w", err)
			}
			if isOwnedTable(table.Family, table.Name) {
				observedTables[tableKey(table.Family, table.Name)] = true
			}
		}
		if raw, ok := object["chain"]; ok {
			var chain struct {
				Family string `json:"family"`
				Table  string `json:"table"`
				Name   string `json:"name"`
			}
			if err := json.Unmarshal(raw, &chain); err != nil {
				return NFTDiff{}, fmt.Errorf("decode nftables chain: %w", err)
			}
			if isOwnedTable(chain.Family, chain.Table) {
				observedChains[chainKey(chain.Family, chain.Table, chain.Name)] = true
			}
		}
		if raw, ok := object["rule"]; ok {
			var rule struct {
				Family  string `json:"family"`
				Table   string `json:"table"`
				Chain   string `json:"chain"`
				Comment string `json:"comment"`
			}
			if err := json.Unmarshal(raw, &rule); err != nil {
				return NFTDiff{}, fmt.Errorf("decode nftables rule: %w", err)
			}
			if isOwnedTable(rule.Family, rule.Table) {
				if rule.Comment == "" {
					observedRules[chainKey(rule.Family, rule.Table, rule.Chain)+":<uncommented>"] = true
				} else {
					observedRules[rule.Comment] = true
				}
			}
		}
	}

	diff := NFTDiff{}
	for _, table := range expectedTables() {
		if !observedTables[table] {
			diff.MissingTables = append(diff.MissingTables, table)
		}
	}
	for _, chain := range expectedChains() {
		if !observedChains[chain] {
			diff.MissingChains = append(diff.MissingChains, chain)
		}
	}
	for _, rule := range expectedRuleComments(plan) {
		if !observedRules[rule] {
			diff.MissingRules = append(diff.MissingRules, rule)
		}
	}
	for rule := range observedRules {
		if !expectedRuleCommentSet(plan)[rule] {
			diff.UnexpectedRules = append(diff.UnexpectedRules, rule)
		}
	}
	sort.Strings(diff.MissingTables)
	sort.Strings(diff.MissingChains)
	sort.Strings(diff.MissingRules)
	sort.Strings(diff.UnexpectedRules)
	return diff, nil
}

func isOwnedTable(family, name string) bool {
	return family == "inet" && name == FilterTable || family == "ip" && name == NATTable
}

func tableKey(family, name string) string { return family + "/" + name }

func chainKey(family, table, chain string) string { return family + "/" + table + "/" + chain }

func expectedTables() []string {
	return []string{tableKey("inet", FilterTable), tableKey("ip", NATTable)}
}

func expectedChains() []string {
	return []string{
		chainKey("inet", FilterTable, "input"),
		chainKey("inet", FilterTable, "forward"),
		chainKey("inet", FilterTable, "output"),
		chainKey("ip", NATTable, "postrouting"),
	}
}

func expectedRuleComments(plans ...Plan) []string {
	comments := []string{
		"boetticher:input-loopback",
		"boetticher:input-established",
		"boetticher:input-wan-dhcp",
		"boetticher:input-zone-dhcp",
		"boetticher:input-sandbox-dns-udp",
		"boetticher:input-sandbox-dns-tcp",
		"boetticher:input-sandbox-ntp",
		"boetticher:input-mgmt-ssh",
		"boetticher:forward-established",
		"boetticher:forward-sandbox-trusted-drop",
		"boetticher:forward-sandbox-servers-drop",
		"boetticher:forward-sandbox-mgmt-drop",
		"boetticher:forward-trusted-servers-tcp",
		"boetticher:forward-trusted-servers-udp",
		"boetticher:forward-trusted-mgmt",
		"boetticher:forward-servers-dns-tcp",
		"boetticher:forward-servers-dns-udp",
		"boetticher:forward-servers-monitoring",
		"boetticher:forward-mgmt-servers-tcp",
		"boetticher:forward-mgmt-servers-udp",
		"boetticher:forward-mgmt-trusted-icmp",
		"boetticher:forward-sandbox-internet",
		"boetticher:forward-trusted-internet",
		"boetticher:forward-servers-internet-tcp",
		"boetticher:forward-servers-internet-udp",
		"boetticher:forward-mgmt-internet",
		"boetticher:nat-trusted",
		"boetticher:nat-servers",
		"boetticher:nat-sandbox",
		"boetticher:nat-mgmt",
	}
	if len(plans) == 0 {
		return comments
	}
	plan := plans[0]
	for _, rule := range plan.Rules {
		if !strings.HasPrefix(rule.Name, "module ") || rule.Action != "allow" || rule.SourceCIDR == "" || rule.From == "" || rule.To == "" || (rule.DestinationCIDR == "" && rule.DestinationHost == "") {
			continue
		}
		comments = append(comments, "boetticher:module-"+safeRuleToken(rule.Name))
		if rule.To == "WAN" && rule.DestinationCIDR != "0.0.0.0/0" {
			comments = append(comments, "boetticher:module-"+safeRuleToken(rule.Name)+"-arbitrary-egress-drop")
		}
	}
	if plan.TailnetExitNode {
		comments = append(comments, "boetticher:module-tailnet_router_internet_exit_egress", "boetticher:nat-tailnet-exit")
	}
	return comments
}

func expectedRuleCommentSet(plans ...Plan) map[string]bool {
	set := make(map[string]bool, len(expectedRuleComments(plans...)))
	for _, value := range expectedRuleComments(plans...) {
		set[value] = true
	}
	return set
}
