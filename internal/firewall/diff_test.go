package firewall

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestCompareNFTIgnoresUnrelatedTablesAndFindsOwnedDrift(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	objects := completeOwnedNFTObjects(t, plan)
	objects = append(objects, map[string]any{"table": map[string]any{"family": "inet", "name": "operator_state"}})
	objects = append(objects, map[string]any{"rule": map[string]any{"family": "inet", "table": "operator_state", "chain": "input", "comment": "operator-owned"}})
	data, err := json.Marshal(map[string]any{"nftables": objects})
	if err != nil {
		t.Fatal(err)
	}
	diff, err := CompareNFT(plan, data)
	if err != nil {
		t.Fatal(err)
	}
	if !diff.Current() {
		t.Fatalf("complete owned ruleset was reported as drift: %#v", diff)
	}

	objects = append(objects, map[string]any{"rule": map[string]any{"family": "inet", "table": FilterTable, "chain": "forward", "comment": "boetticher:unexpected", "expr": []any{map[string]any{"accept": nil}}}})
	data, err = json.Marshal(map[string]any{"nftables": objects})
	if err != nil {
		t.Fatal(err)
	}
	diff, err = CompareNFT(plan, data)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.UnexpectedRules) != 1 || diff.UnexpectedRules[0] != "boetticher:unexpected" {
		t.Fatalf("unexpected owned rule was not reported: %#v", diff)
	}
	objects = append(objects, map[string]any{"rule": map[string]any{"family": "inet", "table": FilterTable, "chain": "forward", "expr": []any{map[string]any{"accept": nil}}}})
	data, err = json.Marshal(map[string]any{"nftables": objects})
	if err != nil {
		t.Fatal(err)
	}
	diff, err = CompareNFT(plan, data)
	if err != nil {
		t.Fatal(err)
	}
	foundUncommented := false
	for _, unexpected := range diff.UnexpectedRules {
		if unexpected == "inet/boetticher_filter/forward:<uncommented>" {
			foundUncommented = true
			break
		}
	}
	if !foundUncommented {
		t.Fatalf("uncommented owned rule was not reported: %#v", diff)
	}
}

func TestCompareNFTReportsMissingOwnedObjects(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	data := []byte(fmt.Sprintf(`{"nftables":[{"table":{"family":"inet","name":"%s"}}]}`, FilterTable))
	diff, err := CompareNFT(plan, data)
	if err != nil {
		t.Fatal(err)
	}
	ruleset, err := RenderNFT(plan)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := parseRenderedNFTContract(ruleset)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.MissingTables) != 1 || len(diff.MissingChains) != len(expected.chains) || len(diff.MissingRules) != len(mustExpectedRuleComments(t, plan)) {
		t.Fatalf("missing owned objects were not reported completely: %#v", diff)
	}
}

func TestCompareNFTMatchesTheCurrentRenderedRuleset(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	ruleset, err := RenderNFT(plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ruleset, "forward-servers-monitoring") {
		t.Fatal("obsolete monitoring rule remains in the rendered ruleset")
	}
	comments := mustExpectedRuleComments(t, plan)
	if len(comments) < 40 {
		t.Fatalf("rendered ruleset exposed only %d owned comments", len(comments))
	}
}

func TestCompareNFTDetectsPolicySetAndRuleOrderDrift(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("semantic-drift", "age1semanticdrift"))
	if err != nil {
		t.Fatal(err)
	}
	objects := completeOwnedNFTObjects(t, plan)
	for _, object := range objects {
		if chain, ok := object["chain"].(map[string]any); ok && chain["name"] == "forward" {
			chain["policy"] = "accept"
			break
		}
	}
	for _, object := range objects {
		if set, ok := object["set"].(map[string]any); ok && set["name"] == "sandbox_net" {
			set["elem"] = []string{"10.10.20.0/24"}
			break
		}
	}
	forwardRuleIndexes := []int{}
	for index, object := range objects {
		if rule, ok := object["rule"].(map[string]any); ok && rule["chain"] == "forward" && rule["table"] == FilterTable {
			forwardRuleIndexes = append(forwardRuleIndexes, index)
		}
	}
	if len(forwardRuleIndexes) < 2 {
		t.Fatal("fixture did not produce two forward rules")
	}
	first, second := forwardRuleIndexes[0], forwardRuleIndexes[1]
	objects[first], objects[second] = objects[second], objects[first]
	data, err := json.Marshal(map[string]any{"nftables": objects})
	if err != nil {
		t.Fatal(err)
	}
	diff, err := CompareNFT(plan, data)
	if err != nil {
		t.Fatal(err)
	}
	if diff.Current() || len(diff.SemanticDrift) == 0 {
		t.Fatalf("semantic policy drift was not detected: %#v", diff)
	}
}

func TestCompareNFTRejectsOwnedRuleWithoutExpression(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("expression-drift", "age1expressiondrift"))
	if err != nil {
		t.Fatal(err)
	}
	objects := completeOwnedNFTObjects(t, plan)
	for _, object := range objects {
		if rule, ok := object["rule"].(map[string]any); ok && rule["table"] == FilterTable && rule["comment"] == "boetticher:input-loopback" {
			rule["expr"] = nil
			break
		}
	}
	data, err := json.Marshal(map[string]any{"nftables": objects})
	if err != nil {
		t.Fatal(err)
	}
	diff, err := CompareNFT(plan, data)
	if err != nil {
		t.Fatal(err)
	}
	if diff.Current() || len(diff.SemanticDrift) == 0 {
		t.Fatalf("missing rule expression was not detected: %#v", diff)
	}
}

func mustExpectedRuleComments(t *testing.T, plan Plan) []string {
	t.Helper()
	comments, err := expectedRuleComments(plan)
	if err != nil {
		t.Fatal(err)
	}
	return comments
}

func completeOwnedNFTObjects(t *testing.T, plan Plan) []map[string]any {
	t.Helper()
	ruleset, err := RenderNFT(plan)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := parseRenderedNFTContract(ruleset)
	if err != nil {
		t.Fatal(err)
	}
	objects := make([]map[string]any, 0, len(expected.tables)+len(expected.chains)+len(expected.sets))
	for table := range expected.tables {
		parts := strings.SplitN(table, "/", 2)
		objects = append(objects, map[string]any{"table": map[string]any{"family": parts[0], "name": parts[1]}})
	}
	for chain, definition := range expected.chains {
		parts := strings.Split(chain, "/")
		value := map[string]any{"family": parts[0], "table": parts[1], "name": parts[2]}
		if definition.Type != "" {
			value["type"] = definition.Type
		}
		if definition.Hook != "" {
			value["hook"] = definition.Hook
		}
		if definition.Policy != "" {
			value["policy"] = definition.Policy
		}
		objects = append(objects, map[string]any{"chain": value})
	}
	for key, definition := range expected.sets {
		parts := strings.Split(key, "/")
		value := map[string]any{"family": parts[0], "table": parts[1], "name": parts[2], "type": definition.Type, "elem": definition.Elements}
		if len(definition.Flags) > 0 {
			value["flags"] = definition.Flags
		}
		objects = append(objects, map[string]any{"set": value})
	}
	for chain, comments := range expected.rules {
		parts := strings.Split(chain, "/")
		for _, comment := range comments {
			objects = append(objects, map[string]any{"rule": map[string]any{
				"family": parts[0], "table": parts[1], "chain": parts[2], "comment": comment,
				"expr": []any{map[string]any{"counter": map[string]any{"packets": 1, "bytes": 1}}, map[string]any{"accept": nil}},
			}})
		}
	}
	return objects
}
