package firewallmodule

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestParseFirewallSafetyStatusRequiresFixedMarker(t *testing.T) {
	ok, err := parseFirewallSafetyStatus([]byte(`{"exitcode":0,"out-data":"BOETTICHER_SAFETY_OK\n"}`))
	if err != nil || !ok {
		t.Fatalf("valid safety status = %v, %v", ok, err)
	}
	if ok, err := parseFirewallSafetyStatus([]byte(`{"exitcode":1,"out-data":"BOETTICHER_SAFETY_OK"}`)); err != nil || ok {
		t.Fatalf("failed command accepted: %v, %v", ok, err)
	}
	if _, err := parseFirewallSafetyStatus([]byte(`{"out-data":"BOETTICHER_SAFETY_OK"}`)); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("missing exit code not rejected: %v", err)
	}
	if _, err := parseFirewallSafetyStatus([]byte(`{"exitcode":0,"out-data":"ok"}`)); err == nil || !strings.Contains(err.Error(), "success marker") {
		t.Fatalf("wrong marker not rejected: %v", err)
	}
}

func TestParseVPNRuntimeStatusRequiresInterfaceAndHandshakeEvidence(t *testing.T) {
	now := time.Now().Unix()
	status, err := parseVPNRuntimeStatus(`[{"ifname":"airvpn","operstate":"UP"}]
peer-public-key ` + fmt.Sprint(now) + `
peer-public-key 1024 2048`)
	if err != nil || !status.InterfaceUp || !status.PeerSeen || status.RxBytes != 1024 || status.TxBytes != 2048 {
		t.Fatalf("runtime status=%+v err=%v", status, err)
	}
	if status.LatestHandshake.IsZero() {
		t.Fatal("handshake timestamp was not observed")
	}
}

func TestParseVPNRuntimeStatusAcceptsWireGuardUnknownOperstateWithUpFlags(t *testing.T) {
	now := time.Now().Unix()
	status, err := parseVPNRuntimeStatus(`[{"ifname":"airvpn","flags":["POINTOPOINT","NOARP","UP","LOWER_UP"],"operstate":"UNKNOWN"}]
peer ` + fmt.Sprint(now))
	if err != nil || !status.InterfaceUp || !status.PeerSeen {
		t.Fatalf("runtime status=%+v err=%v", status, err)
	}
}

func TestVPNClientMTURouteVerifierUsesNativeLABRouteShape(t *testing.T) {
	line := "10.10.20.230 dev br-lab.20 proto static scope link mtu 1320"
	if !hasVPNClientMTURoute(line, "10.10.20.230", "br-lab.20", "1320") {
		t.Fatal("native LAB MTU route was rejected")
	}
	for _, invalid := range []struct{ device, mtu string }{{"airvpn", "1320"}, {"br-lab.20", "1280"}} {
		if hasVPNClientMTURoute(line, "10.10.20.230", invalid.device, invalid.mtu) {
			t.Fatalf("invalid route accepted: device=%s mtu=%s", invalid.device, invalid.mtu)
		}
	}
	if hasVPNClientMTURoute("10.10.20.230/24 dev br-lab.20 proto static scope link mtu 1320", "10.10.20.230", "br-lab.20", "1320") {
		t.Fatal("non-host route prefix was accepted")
	}
}
