package arrstack

import "testing"

func TestContractIdentityAndVPNForward(t *testing.T) {
	r := Reservation()
	if r.Name != GuestName || r.Zone != "SERVERS" || r.Address != GuestAddress || r.MAC != GuestMAC {
		t.Fatalf("reservation = %#v", r)
	}
	f := VPNForward()
	if f.Name != "arrstack-qbittorrent" || f.Reservation != GuestName || f.Port != 35796 {
		t.Fatalf("forward = %#v", f)
	}
	if len(f.Protocols) != 2 || f.Protocols[0] != "tcp" || f.Protocols[1] != "udp" {
		t.Fatalf("protocols = %#v", f.Protocols)
	}
}
