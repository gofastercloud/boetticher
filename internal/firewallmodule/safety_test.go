package firewallmodule

import (
	"strings"
	"testing"
)

func TestDefaultSafetyConfigRetainsProtectedRangesWithEmptyDynamicSets(t *testing.T) {
	cfg := DefaultSafetyConfig()
	if len(cfg.ProtectedIPv4) != 4 {
		t.Fatalf("protected ranges = %#v, want one /28 for each fixed zone", cfg.ProtectedIPv4)
	}
	if len(cfg.ClientIPv4) != 0 || len(cfg.ForwardTuples) != 0 {
		t.Fatalf("initial dynamic sets are not empty: clients=%#v forwards=%#v", cfg.ClientIPv4, cfg.ForwardTuples)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default safety config is invalid: %v", err)
	}
}

func TestRenderSafetyUCIUsesOwnedNativeSetTypes(t *testing.T) {
	text, err := RenderSafetyUCI(DefaultSafetyConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"config ipset 'boetticher_vpn_protected4'",
		"option name 'boetticher_vpn_protected4'",
		"option family 'ipv4'",
		"list match 'src_net'",
		"list match 'dest_net'",
		"config ipset 'boetticher_vpn_clients4'",
		"config ipset 'boetticher_vpn_forwards_tcp4'",
		"config ipset 'boetticher_vpn_forwards_udp4'",
		"list match 'dest_ip'",
		"list match 'dest_port'",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("native safety UCI missing %q:\n%s", want, text)
		}
	}
}

func TestRenderSafetyUCIRequiresNativeSetNames(t *testing.T) {
	text, err := RenderSafetyUCI(DefaultSafetyConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{SafetyHomeSet, SafetyLabSet, SafetyProtectedSet, SafetyClientSet, SafetyForwardTCPSet, SafetyForwardUDPSet} {
		if !strings.Contains(text, "option name '"+name+"'") {
			t.Fatalf("native safety set %s has no explicit name: %s", name, text)
		}
	}
}

func TestSafetyAssetManifestListsOnlyStaticAssetPaths(t *testing.T) {
	manifest := RenderSafetyAssetManifest()
	for _, want := range []string{
		"/usr/share/nftables.d/chain-pre/input/10-boetticher-safety.nft",
		"/usr/share/nftables.d/chain-pre/forward/10-boetticher-safety.nft",
		"/usr/share/nftables.d/chain-pre/output/10-boetticher-safety.nft",
	} {
		if !strings.Contains(manifest, want) {
			t.Fatalf("asset manifest missing %q: %s", want, manifest)
		}
	}
	if strings.Contains(manifest, "table inet fw4") || strings.Contains(manifest, "ct state established accept") {
		t.Fatal("asset manifest unexpectedly contains expanded ruleset content")
	}
}

func TestSafetyConfigRejectsInvalidOrOverlappingInputs(t *testing.T) {
	bad := DefaultSafetyConfig()
	bad.ProtectedIPv4 = append(bad.ProtectedIPv4, "10.10.5.225/32")
	if err := bad.Validate(); err == nil {
		t.Fatal("overlapping protected range was accepted")
	}
	bad = DefaultSafetyConfig()
	bad.ClientIPv4 = []string{"10.10.5.223"}
	if err := bad.Validate(); err == nil {
		t.Fatal("client outside protected ranges was accepted")
	}
	bad = DefaultSafetyConfig()
	bad.ClientIPv4 = []string{"10.10.20.225"}
	bad.ForwardTuples = []ForwardTuple{{Address: "10.10.20.226", Protocol: "tcp", Port: 40000}}
	if err := bad.Validate(); err == nil {
		t.Fatal("forward destination without a declared client was accepted")
	}
	bad.ForwardTuples = []ForwardTuple{{Address: "10.10.20.225", Protocol: "icmp", Port: 1}}
	if err := bad.Validate(); err == nil {
		t.Fatal("unsupported forwarding protocol was accepted")
	}
}

func TestRenderSafetyUCIEmitsProtocolSeparatedTupleSets(t *testing.T) {
	cfg := DefaultSafetyConfig()
	cfg.ClientIPv4 = []string{"10.10.20.225"}
	cfg.ForwardTuples = []ForwardTuple{
		{Address: "10.10.20.225", Protocol: "udp", Port: 40001},
		{Address: "10.10.20.225", Protocol: "tcp", Port: 40000},
	}
	text, err := RenderSafetyUCI(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tcpAt := strings.Index(text, "config ipset 'boetticher_vpn_forwards_tcp4'")
	udpAt := strings.Index(text, "config ipset 'boetticher_vpn_forwards_udp4'")
	if tcpAt < 0 || udpAt < 0 || tcpAt >= udpAt {
		t.Fatalf("protocol tuple sets are not ordered or both present: %s", text)
	}
	if !strings.Contains(text[tcpAt:udpAt], "10.10.20.225 40000") || !strings.Contains(text[udpAt:], "10.10.20.225 40001") {
		t.Fatalf("tuple entries were not projected into their protocol set: %s", text)
	}
}

func TestSafetyProtectedRangeBoundaries(t *testing.T) {
	for _, address := range []string{"10.10.20.224", "10.10.20.239"} {
		cfg := DefaultSafetyConfig()
		cfg.ClientIPv4 = []string{address}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("protected boundary %s was rejected: %v", address, err)
		}
	}
	for _, address := range []string{"10.10.20.223", "10.10.20.240"} {
		cfg := DefaultSafetyConfig()
		cfg.ClientIPv4 = []string{address}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("neighboring address %s was accepted as protected", address)
		}
	}
}
