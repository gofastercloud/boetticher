package firewall

import "testing"

func TestParseCountersKeepsOnlyOwnedTaggedRules(t *testing.T) {
	data := []byte(`{"nftables":[
{"rule":{"family":"inet","table":"boetticher_filter","chain":"forward","comment":"boetticher:forward-sandbox-internet","expr":[{"counter":{"packets":841,"bytes":9012}},{"accept":null}]}},
{"rule":{"family":"inet","table":"operator_state","chain":"input","comment":"operator:counter","expr":[{"counter":{"packets":999,"bytes":999}}]}},
{"rule":{"family":"inet","table":"boetticher_filter","chain":"forward","comment":"boetticher:forward-mgmt-internet","expr":[{"counter":{"packets":3,"bytes":7}}]}}
]}`)
	counters, err := ParseCounters(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(counters) != 2 {
		t.Fatalf("got %d counters, want 2: %#v", len(counters), counters)
	}
	if counters[0].Rule != "boetticher:forward-mgmt-internet" || counters[0].Packets != 3 || counters[0].Bytes != 7 {
		t.Fatalf("unexpected sorted first counter: %#v", counters[0])
	}
}
