package arrstack

import (
	"os"
	"strings"
	"testing"
)

func TestComposeUsesOwnedBridgeAndPinnedGuestBindings(t *testing.T) {
	b, err := os.ReadFile("compose.contract.yml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "10.10.20.230:35796:35796/tcp") || !strings.Contains(s, "10.10.20.230:35796:35796/udp") {
		t.Fatal("peer port must preserve TCP and UDP")
	}
	for _, want := range []string{"10.10.20.230:443:443", "name: btcr-arrstack0", "com.docker.network.bridge.name: btcr-arrstack0", "subnet: 172.30.20.0/24"} {
		if !strings.Contains(s, want) {
			t.Fatalf("compose contract missing %q", want)
		}
	}
}

func TestBuilderPinsQBitTorrentListenerToThePublishedPeerPort(t *testing.T) {
	b, err := os.ReadFile("../../scripts/build-arrstack.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`Connection\\\\PortRangeMin=${peerPort}`, `Connection\\\\PortRangeMax=${peerPort}`, "ARRSTACK_PEER_PORT"} {
		if !strings.Contains(s, want) {
			t.Fatalf("builder does not render qBittorrent listener contract %q", want)
		}
	}
}
