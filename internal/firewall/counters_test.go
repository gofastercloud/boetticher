package firewall

import (
	"fmt"
	"strings"
	"testing"
)

func TestSemanticCounterCommentIsStableAndBounded(t *testing.T) {
	comment, err := SemanticCounterComment("drop", "forward-sandbox-trusted")
	if err != nil || comment != "boetticher:drop:forward-sandbox-trusted" {
		t.Fatalf("SemanticCounterComment() = %q, %v", comment, err)
	}
	for _, invalid := range []struct{ kind, id string }{{"permit", "x"}, {"drop", "../escape"}, {"drop", "UPPER"}, {"drop", ""}} {
		if _, err := SemanticCounterComment(invalid.kind, invalid.id); err == nil {
			t.Fatalf("invalid semantic counter comment was accepted: %#v", invalid)
		}
	}
	if _, err := SemanticCounterComment("allow", strings.Repeat("x", MaxNFTComment)); err == nil {
		t.Fatal("oversized semantic counter comment was accepted")
	}
}

func TestParseCountersKeepsOnlyOwnedSemanticCounterRules(t *testing.T) {
	data := realisticNFTJSON(841, 9012, 3, 7)
	counters, err := ParseCounters([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(counters) != 2 {
		t.Fatalf("got %d counters, want 2: %#v", len(counters), counters)
	}
	if counters[0].ID != "forward-sandbox-internet" || counters[0].Kind != "allow" || counters[0].Packets != 841 || counters[0].Bytes != 9012 {
		t.Fatalf("unexpected sorted first counter: %#v", counters[0])
	}
	if counters[1].ID != "forward-mgmt-telemetry" || counters[1].Kind != "drop" || counters[1].Packets != 3 || counters[1].Bytes != 7 {
		t.Fatalf("unexpected sorted second counter: %#v", counters[1])
	}
}

func TestParseNFTSnapshotFingerprintIgnoresHandlesCountersAndOrdering(t *testing.T) {
	first := realisticNFTJSON(841, 9012, 3, 7)
	second := strings.ReplaceAll(first, `"handle": 11`, `"handle": 911`)
	second = strings.ReplaceAll(second, `"packets": 841`, `"packets": 100000841`)
	second = strings.ReplaceAll(second, `"bytes": 9012`, `"bytes": 1000009012`)
	second = strings.ReplaceAll(second, `"handle": 12`, `"handle": 912`)
	second = strings.ReplaceAll(second, `"packets": 3`, `"packets": 1003`)
	second = strings.ReplaceAll(second, `"bytes": 7`, `"bytes": 1007`)
	firstSnapshot, err := ParseNFTSnapshot([]byte(first))
	if err != nil {
		t.Fatal(err)
	}
	secondSnapshot, err := ParseNFTSnapshot([]byte(second))
	if err != nil {
		t.Fatal(err)
	}
	if firstSnapshot.Fingerprint != secondSnapshot.Fingerprint {
		t.Fatalf("fingerprint changed for non-structural counter/handle changes: %s != %s", firstSnapshot.Fingerprint, secondSnapshot.Fingerprint)
	}
	changed := strings.Replace(first, `"policy":"drop"`, `"policy":"accept"`, 1)
	changedSnapshot, err := ParseNFTSnapshot([]byte(changed))
	if err != nil {
		t.Fatal(err)
	}
	if changedSnapshot.Fingerprint == firstSnapshot.Fingerprint {
		t.Fatal("fingerprint ignored a structural expression change")
	}
	reordered := strings.Replace(first, `{"table":{"family":"inet","name":"boetticher_filter","handle":1}},
{"chain":{"family":"inet","table":"boetticher_filter","name":"forward","handle":2,"type":"filter","hook":"forward","prio":0,"policy":"drop"}},
`, `{"chain":{"family":"inet","table":"boetticher_filter","name":"forward","handle":2,"type":"filter","hook":"forward","prio":0,"policy":"drop"}},
{"table":{"family":"inet","name":"boetticher_filter","handle":1}},
`, 1)
	reorderedSnapshot, err := ParseNFTSnapshot([]byte(reordered))
	if err != nil {
		t.Fatal(err)
	}
	if reorderedSnapshot.Fingerprint != firstSnapshot.Fingerprint {
		t.Fatal("fingerprint changed for non-structural object ordering")
	}
	setChanged := strings.Replace(first, `"elem":["10.10.40.0/24"]`, `"elem":["10.10.20.0/24"]`, 1)
	setChangedSnapshot, err := ParseNFTSnapshot([]byte(setChanged))
	if err != nil {
		t.Fatal(err)
	}
	if setChangedSnapshot.Fingerprint == firstSnapshot.Fingerprint {
		t.Fatal("fingerprint ignored an owned set structural change")
	}
	setReordered := strings.Replace(first, `"elem":["10.10.40.0/24"]`, `"elem":["10.10.40.0/24","10.10.10.0/24"]`, 1)
	setReordered = strings.Replace(setReordered, `"elem":["10.10.40.0/24","10.10.10.0/24"]`, `"elem":["10.10.10.0/24","10.10.40.0/24"]`, 1)
	setReorderedSnapshot, err := ParseNFTSnapshot([]byte(setReordered))
	if err != nil {
		t.Fatal(err)
	}
	if setReorderedSnapshot.Fingerprint == firstSnapshot.Fingerprint {
		// The fixture has one element in the baseline; the two-element set is a
		// real structural change even though its internal order is normalized.
		t.Fatal("fingerprint unexpectedly ignored an owned set membership change")
	}
	setReorderedBack := strings.Replace(setReordered, `"elem":["10.10.10.0/24","10.10.40.0/24"]`, `"elem":["10.10.40.0/24","10.10.10.0/24"]`, 1)
	backSnapshot, err := ParseNFTSnapshot([]byte(setReorderedBack))
	if err != nil {
		t.Fatal(err)
	}
	if backSnapshot.Fingerprint != setReorderedSnapshot.Fingerprint {
		t.Fatal("fingerprint changed for non-structural set element ordering")
	}
}

func TestParseNFTSnapshotRejectsMalformedOwnedInputAndOversizedInput(t *testing.T) {
	for _, malformed := range []string{
		`{"nftables":[{"rule":{"family":"inet","table":"boetticher_filter","chain":"forward","comment":"boetticher:allow:test","expr":[{"counter":{"packets":"bad","bytes":1}}]}}]}`,
		`{"nftables":[{"rule":{"family":"inet","table":"boetticher_filter","chain":"forward","comment":"boetticher:allow:test","expr":"not-an-array"}}]}`,
		`{"nftables":[{"rule":{"family":"inet","table":"boetticher_filter","chain":"forward","comment":"boetticher:allow:test","expr":[{"counter":{"packets":1}}]}}]}`,
	} {
		if _, err := ParseNFTSnapshot([]byte(malformed)); err == nil {
			t.Fatalf("malformed owned input was accepted: %s", malformed)
		}
	}
	if _, err := ParseNFTSnapshot([]byte(`{"nftables":[` + fmt.Sprintf("%q", strings.Repeat("x", MaxNFTJSONBytes)) + `]}`)); err == nil {
		t.Fatal("oversized nft input was accepted")
	}
}

func TestParseNFTSnapshotIgnoresNonBoetticherRulesEvenWithSameLookingComment(t *testing.T) {
	data := `{"nftables":[
{"table":{"family":"inet","name":"operator_state"}},
{"rule":{"family":"inet","table":"operator_state","chain":"input","comment":42,"expr":[{"counter":{"packets":99,"bytes":99}}]}},
{"rule":{"family":"inet","table":"boetticher_filter","chain":"forward","comment":"operator:rule","expr":[{"counter":{"packets":98,"bytes":98}}]}}
]}`
	snapshot, err := ParseNFTSnapshot([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Counters) != 0 {
		t.Fatalf("non-Boetticher counters were returned: %#v", snapshot.Counters)
	}
}

func realisticNFTJSON(allowPackets, allowBytes, dropPackets, dropBytes uint64) string {
	return fmt.Sprintf(`{"nftables":[
{"metainfo":{"json_schema_version":1}},
{"table":{"family":"inet","name":"operator_state","handle":99}},
{"table":{"family":"inet","name":"boetticher_filter","handle":1}},
{"chain":{"family":"inet","table":"boetticher_filter","name":"forward","handle":2,"type":"filter","hook":"forward","prio":0,"policy":"drop"}},
{"set":{"family":"inet","table":"boetticher_filter","name":"sandbox_net","type":"ipv4_addr","handle":21,"elem":["10.10.40.0/24"]}},
{"rule":{"family":"inet","table":"boetticher_filter","chain":"forward","handle":12,"comment":"boetticher:drop:forward-mgmt-telemetry","expr":[{"counter":{"packets":%d,"bytes":%d}},{"drop":null}]}},
{"rule":{"family":"inet","table":"boetticher_filter","chain":"forward","handle":11,"comment":"boetticher:allow:forward-sandbox-internet","expr":[{"counter":{"packets":%d,"bytes":%d}},{"accept":null}]}},
{"rule":{"family":"inet","table":"boetticher_filter","chain":"forward","handle":13,"comment":"boetticher:input-loopback","expr":[{"accept":null}]}},
{"rule":{"family":"inet","table":"operator_state","chain":"input","handle":14,"comment":"boetticher:allow:operator-rule","expr":[{"counter":{"packets":999,"bytes":999}}]}}
]}`, dropPackets, dropBytes, allowPackets, allowBytes)
}
