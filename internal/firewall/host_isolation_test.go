package firewall

import (
	"github.com/gofastercloud/boetticher/internal/model"
	"testing"
)

func TestHostIsolationUsesActualSandboxGatewayMAC(t *testing.T) {
	s := isolationSite(t)
	p := HostIsolationForSite(s)
	if p.GatewayMAC != "02:00:00:00:01:04" || p.GatewayVMID != 100 || p.Bridge != "vmbr1" {
		t.Fatalf("wrong bridge gateway identity: %#v", p)
	}
	if len(p.Selected) != 1 || p.Selected[0].Gateway != "10.10.20.1" || p.Selected[0].GatewayMAC != model.GatewayInterfaceMAC(3) {
		t.Fatalf("selected client lost its subnet gateway: %#v", p.Selected)
	}
}
