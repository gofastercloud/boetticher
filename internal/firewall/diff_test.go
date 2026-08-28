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
	objects := []map[string]any{
		{"table": map[string]any{"family": "inet", "name": FilterTable}},
		{"table": map[string]any{"family": "ip", "name": NATTable}},
		{"table": map[string]any{"family": "inet", "name": "operator_state"}},
	}
	for _, chain := range []struct{ family, table, name string }{
		{"inet", FilterTable, "input"},
		{"inet", FilterTable, "forward"},
		{"inet", FilterTable, "output"},
		{"ip", NATTable, "postrouting"},
	} {
		objects = append(objects, map[string]any{"chain": map[string]any{"family": chain.family, "table": chain.table, "name": chain.name}})
	}
	for _, comment := range mustExpectedRuleComments(t, plan) {
		objects = append(objects, map[string]any{"rule": map[string]any{"family": "inet", "table": FilterTable, "chain": "forward", "comment": comment}})
	}
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

	objects = append(objects, map[string]any{"rule": map[string]any{"family": "inet", "table": FilterTable, "chain": "forward", "comment": "boetticher:unexpected"}})
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
	if len(diff.MissingTables) != 1 || len(diff.MissingChains) != 4 || len(diff.MissingRules) != len(mustExpectedRuleComments(t, plan)) {
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

func mustExpectedRuleComments(t *testing.T, plan Plan) []string {
	t.Helper()
	comments, err := expectedRuleComments(plan)
	if err != nil {
		t.Fatal(err)
	}
	return comments
}
