package firewall

import "testing"

func TestHostIsolationUsesActualSandboxGatewayMAC(t *testing.T) {
	s := isolationSite(t)
	p := HostIsolationForSite(s)
	if p.GatewayMAC != "02:00:00:00:01:04" || p.GatewayVMID != 100 || p.Bridge != "vmbr1" {
		t.Fatalf("wrong bridge gateway identity: %#v", p)
	}
}
