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
	SemanticDrift   []string `json:"semantic_drift,omitempty"`
}

func (d NFTDiff) Current() bool {
	return len(d.MissingTables) == 0 && len(d.MissingChains) == 0 && len(d.MissingRules) == 0 && len(d.UnexpectedRules) == 0 && len(d.SemanticDrift) == 0
}

// CompareNFT compares the JSON emitted by `nft --json list ruleset` with the
// deterministic boetticher projection. The comparison is bounded to owned
// tables and validates object structure, chain policy, set membership, rule
// location/order, and expression presence. Comments identify generated rules
// for diagnostics; they are not the semantic correctness check by themselves.
func CompareNFT(plan Plan, live []byte) (NFTDiff, error) {
	if plan.Mode != model.GatewayModeManaged {
		return NFTDiff{}, fmt.Errorf("nftables comparison is only available in managed gateway mode")
	}
	ruleset, err := RenderNFT(plan)
	if err != nil {
		return NFTDiff{}, err
	}
	expected, err := parseRenderedNFTContract(ruleset)
	if err != nil {
		return NFTDiff{}, fmt.Errorf("parse expected nftables policy: %w", err)
	}
	// ParseNFTSnapshot provides bounded JSON decoding and normalized owned
	// object validation, including expression and set shape checks.
	if _, err := ParseNFTSnapshot(live); err != nil {
		return NFTDiff{}, err
	}
	var document struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(live, &document); err != nil {
		return NFTDiff{}, fmt.Errorf("decode nftables JSON: %w", err)
	}
	observedTables := map[string]bool{}
	observedChains := map[string]observedNFTChain{}
	observedSets := map[string]observedNFTSet{}
	observedRules := map[string][]observedNFTRule{}
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
				var details struct {
					Type   string `json:"type"`
					Hook   string `json:"hook"`
					Policy string `json:"policy"`
					Prio   any    `json:"prio"`
				}
				if err := json.Unmarshal(raw, &details); err != nil {
					return NFTDiff{}, fmt.Errorf("decode nftables chain details: %w", err)
				}
				observedChains[chainKey(chain.Family, chain.Table, chain.Name)] = observedNFTChain{Type: details.Type, Hook: details.Hook, Policy: details.Policy}
			}
		}
		if raw, ok := object["set"]; ok {
			var set struct {
				Family string            `json:"family"`
				Table  string            `json:"table"`
				Name   string            `json:"name"`
				Type   string            `json:"type"`
				Flags  []string          `json:"flags"`
				Elem   []json.RawMessage `json:"elem"`
			}
			if err := json.Unmarshal(raw, &set); err != nil {
				return NFTDiff{}, fmt.Errorf("decode nftables set: %w", err)
			}
			if isOwnedTable(set.Family, set.Table) {
				observedSets[setKey(set.Family, set.Table, set.Name)] = observedNFTSet{Type: set.Type, Flags: append([]string(nil), set.Flags...), Elements: normalizeSetElements(set.Elem)}
			}
		}
		if raw, ok := object["rule"]; ok {
			var rule struct {
				Family  string          `json:"family"`
				Table   string          `json:"table"`
				Chain   string          `json:"chain"`
				Comment string          `json:"comment"`
				Expr    json.RawMessage `json:"expr"`
			}
			if err := json.Unmarshal(raw, &rule); err != nil {
				return NFTDiff{}, fmt.Errorf("decode nftables rule: %w", err)
			}
			if isOwnedTable(rule.Family, rule.Table) {
				observedRules[chainKey(rule.Family, rule.Table, rule.Chain)] = append(observedRules[chainKey(rule.Family, rule.Table, rule.Chain)], observedNFTRule{Comment: rule.Comment, Expr: rule.Expr})
			}
		}
	}

	diff := NFTDiff{}
	for table := range expected.tables {
		if !observedTables[table] {
			diff.MissingTables = append(diff.MissingTables, table)
		}
	}
	for chain, want := range expected.chains {
		observed, ok := observedChains[chain]
		if !ok {
			diff.MissingChains = append(diff.MissingChains, chain)
			continue
		}
		if want.Type != "" && observed.Type != want.Type {
			diff.SemanticDrift = append(diff.SemanticDrift, fmt.Sprintf("%s: chain type %q, want %q", chain, observed.Type, want.Type))
		}
		if want.Hook != "" && observed.Hook != want.Hook {
			diff.SemanticDrift = append(diff.SemanticDrift, fmt.Sprintf("%s: chain hook %q, want %q", chain, observed.Hook, want.Hook))
		}
		if want.Policy != "" && observed.Policy != want.Policy {
			diff.SemanticDrift = append(diff.SemanticDrift, fmt.Sprintf("%s: chain policy %q, want %q", chain, observed.Policy, want.Policy))
		}
	}
	for key, want := range expected.sets {
		observed, ok := observedSets[key]
		if !ok {
			diff.SemanticDrift = append(diff.SemanticDrift, key+": set missing")
			continue
		}
		if want.Type != observed.Type || !equalStringSet(want.Flags, observed.Flags) || !equalStringSet(want.Elements, observed.Elements) {
			diff.SemanticDrift = append(diff.SemanticDrift, key+": set definition differs")
		}
	}
	for key := range observedChains {
		if _, ok := expected.chains[key]; !ok {
			diff.SemanticDrift = append(diff.SemanticDrift, key+": unexpected owned chain")
		}
	}
	for key := range observedSets {
		if _, ok := expected.sets[key]; !ok {
			diff.SemanticDrift = append(diff.SemanticDrift, key+": unexpected owned set")
		}
	}
	for chain, want := range expected.rules {
		observed := observedRules[chain]
		if len(observed) < len(want) {
			for _, comment := range want[len(observed):] {
				diff.MissingRules = append(diff.MissingRules, comment)
			}
		}
		if len(observed) > len(want) {
			for _, rule := range observed[len(want):] {
				diff.UnexpectedRules = append(diff.UnexpectedRules, observedRuleLabel(chain, rule))
			}
		}
		limit := len(observed)
		if len(want) < limit {
			limit = len(want)
		}
		for index := 0; index < limit; index++ {
			if observed[index].Comment != want[index] {
				if observed[index].Comment != "" {
					diff.UnexpectedRules = append(diff.UnexpectedRules, observed[index].Comment)
				}
				diff.SemanticDrift = append(diff.SemanticDrift, fmt.Sprintf("%s: rule order or identity differs at position %d", chain, index))
			}
			if len(observed[index].Expr) == 0 || string(observed[index].Expr) == "null" {
				diff.SemanticDrift = append(diff.SemanticDrift, fmt.Sprintf("%s: rule %q has no expression", chain, observed[index].Comment))
			}
		}
	}
	for chain, observed := range observedRules {
		if _, ok := expected.rules[chain]; ok {
			continue
		}
		for _, rule := range observed {
			diff.UnexpectedRules = append(diff.UnexpectedRules, observedRuleLabel(chain, rule))
		}
	}
	sort.Strings(diff.MissingTables)
	sort.Strings(diff.MissingChains)
	sort.Strings(diff.MissingRules)
	sort.Strings(diff.UnexpectedRules)
	sort.Strings(diff.SemanticDrift)
	return diff, nil
}

func isOwnedTable(family, name string) bool {
	return family == "inet" && name == FilterTable || family == "ip" && name == NATTable
}

func tableKey(family, name string) string { return family + "/" + name }

func chainKey(family, table, chain string) string { return family + "/" + table + "/" + chain }

func setKey(family, table, name string) string { return family + "/" + table + "/" + name }

func expectedRuleComments(plan Plan) ([]string, error) {
	ruleset, err := RenderNFT(plan)
	if err != nil {
		return nil, fmt.Errorf("render expected nftables rules: %w", err)
	}
	contract, err := parseRenderedNFTContract(ruleset)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, comments := range contract.rules {
		for _, comment := range comments {
			seen[comment] = true
		}
	}
	comments := make([]string, 0, len(seen))
	for comment := range seen {
		comments = append(comments, comment)
	}
	sort.Strings(comments)
	return comments, nil
}

type expectedNFTContract struct {
	tables map[string]bool
	chains map[string]expectedNFTChain
	sets   map[string]expectedNFTSet
	rules  map[string][]string
}

type expectedNFTChain struct {
	Type   string
	Hook   string
	Policy string
}

type expectedNFTSet struct {
	Type     string
	Flags    []string
	Elements []string
}

type observedNFTChain struct {
	Type   string
	Hook   string
	Policy string
}

type observedNFTSet struct {
	Type     string
	Flags    []string
	Elements []string
}

type observedNFTRule struct {
	Comment string
	Expr    json.RawMessage
}

func parseRenderedNFTContract(ruleset string) (expectedNFTContract, error) {
	contract := expectedNFTContract{tables: map[string]bool{}, chains: map[string]expectedNFTChain{}, sets: map[string]expectedNFTSet{}, rules: map[string][]string{}}
	family, table, chain := "", "", ""
	for _, rawLine := range strings.Split(ruleset, "\n") {
		line := strings.TrimSpace(rawLine)
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "table" {
			family, table, chain = fields[1], fields[2], ""
			contract.tables[tableKey(family, table)] = true
			continue
		}
		if len(fields) >= 2 && fields[0] == "chain" {
			chain = strings.TrimSuffix(fields[1], "{")
			contract.chains[chainKey(family, table, chain)] = expectedNFTChain{}
			continue
		}
		if family == "" || table == "" {
			continue
		}
		if len(fields) >= 2 && fields[0] == "set" {
			set, err := parseRenderedNFTSet(line)
			if err != nil {
				return expectedNFTContract{}, err
			}
			contract.sets[setKey(family, table, set.Name)] = expectedNFTSet{Type: set.Type, Flags: set.Flags, Elements: set.Elements}
			continue
		}
		if chain != "" && strings.HasPrefix(line, "type ") {
			key := chainKey(family, table, chain)
			definition := contract.chains[key]
			definition.Type = tokenAfter(line, "type")
			definition.Hook = tokenAfter(line, "hook")
			definition.Policy = tokenAfter(line, "policy")
			contract.chains[key] = definition
			continue
		}
		if chain != "" {
			comment, err := renderedRuleComment(line)
			if err != nil {
				return expectedNFTContract{}, err
			}
			if comment != "" {
				key := chainKey(family, table, chain)
				contract.rules[key] = append(contract.rules[key], comment)
			}
		}
	}
	return contract, nil
}

type renderedNFTSet struct {
	Name     string
	Type     string
	Flags    []string
	Elements []string
}

func parseRenderedNFTSet(line string) (renderedNFTSet, error) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return renderedNFTSet{}, fmt.Errorf("rendered nftables set is incomplete")
	}
	set := renderedNFTSet{Name: fields[1]}
	set.Type = betweenNFT(line, "type ", ";")
	flags := betweenNFT(line, "flags ", "elements =")
	for _, flag := range strings.Split(flags, ";") {
		if flag = strings.TrimSpace(flag); flag != "" {
			set.Flags = append(set.Flags, flag)
		}
	}
	elements := betweenNFT(line, "elements = {", "}")
	for _, value := range strings.Split(elements, ",") {
		if value = strings.TrimSpace(value); value != "" {
			set.Elements = append(set.Elements, value)
		}
	}
	if set.Type == "" {
		return renderedNFTSet{}, fmt.Errorf("rendered nftables set %q has no type", set.Name)
	}
	return set, nil
}

func renderedRuleComment(line string) (string, error) {
	const marker = `comment "`
	start := strings.Index(line, marker)
	if start < 0 {
		return "", nil
	}
	valueStart := start + len(marker)
	end := strings.IndexByte(line[valueStart:], '"')
	if end < 0 {
		return "", fmt.Errorf("rendered nftables rule comment is unterminated")
	}
	return line[valueStart : valueStart+end], nil
}

func betweenNFT(value, start, end string) string {
	from := strings.Index(value, start)
	if from < 0 {
		return ""
	}
	from += len(start)
	to := strings.Index(value[from:], end)
	if to < 0 {
		return ""
	}
	return strings.TrimSpace(value[from : from+to])
}

func tokenAfter(value, token string) string {
	fields := strings.Fields(value)
	for index, field := range fields {
		if field != token || index+1 >= len(fields) {
			continue
		}
		return strings.Trim(fields[index+1], ";")
	}
	return ""
}

func normalizeSetElements(elements []json.RawMessage) []string {
	result := make([]string, 0, len(elements))
	for _, raw := range elements {
		var value any
		if json.Unmarshal(raw, &value) == nil {
			if text, ok := value.(string); ok {
				result = append(result, text)
				continue
			}
			if data, err := json.Marshal(value); err == nil {
				result = append(result, string(data))
			}
		}
	}
	sort.Strings(result)
	return result
}

func equalStringSet(left, right []string) bool {
	left = append([]string(nil), left...)
	right = append([]string(nil), right...)
	sort.Strings(left)
	sort.Strings(right)
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func observedRuleLabel(chain string, rule observedNFTRule) string {
	if rule.Comment != "" {
		return rule.Comment
	}
	return chain + ":<uncommented>"
}
