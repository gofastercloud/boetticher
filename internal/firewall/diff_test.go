package firewall

import (
	"encoding/json"
	"fmt"
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
	for _, comment := range expectedRuleComments() {
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
	if len(diff.MissingTables) != 1 || len(diff.MissingChains) != 4 || len(diff.MissingRules) != len(expectedRuleComments()) {
		t.Fatalf("missing owned objects were not reported completely: %#v", diff)
	}
}
