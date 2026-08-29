package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/firewall"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	"github.com/gofastercloud/boetticher/internal/proxmox"
)

func TestParseGatewayStatus(t *testing.T) {
	status, err := parseGatewayStatus("forwarding=1\nservice.nftables=active\nservice.kea-dhcp4-server=active\nservice.kea-dhcp-ddns-server=active\nservice.dnsmasq=active\niface.wan0=wan0 UP 192.0.2.10/24\niface.trusted0=trusted0 UP 10.10.30.1/24\niface.servers0=servers0 UP 10.10.20.1/24\niface.sandbox0=sandbox0 UP 10.10.40.1/24\niface.mgmt0=mgmt0 UP 10.10.99.1/24\niface.transit0=transit0 UP 10.10.5.1/24\niface.infra0=infra0 UP 10.10.10.1/24\nupstream.interface=wan0\nupstream.mac=02:00:00:00:01:01\nupstream.address=192.0.2.10/24\nupstream.gateway=192.0.2.1\n")
	if err != nil {
		t.Fatal(err)
	}
	if status.Forwarding != "1" || status.Services["nftables"] != "active" || status.Interfaces["mgmt0"] != "mgmt0 UP 10.10.99.1/24" || status.Upstream.Address != "192.0.2.10/24" || status.Upstream.Gateway != "192.0.2.1" {
		t.Fatalf("unexpected gateway status: %#v", status)
	}
}

func TestParseGatewayStatusRejectsIncompleteOutput(t *testing.T) {
	if _, err := parseGatewayStatus("forwarding=0\nservice.nftables=inactive\n"); err == nil {
		t.Fatal("incomplete gateway status was accepted")
	}
}

func TestGatewayStatusScriptDoesNotDependOnInterfaceEnumeration(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "images", "firewall", "runtime", "inspect-firewall.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, role := range []string{"wan0", "trusted0", "servers0", "sandbox0", "mgmt0", "transit0", "infra0"} {
		if !strings.Contains(text, role) {
			t.Fatalf("gateway status script does not inspect stable role interface %q", role)
		}
	}
	for _, forbidden := range []string{"sh -c", "eval ", "systemctl \"$2\"", "nft \"$2\""} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("firewall inspection helper contains an unbounded operation %q", forbidden)
		}
	}
}

func TestGatewayStatusScriptRejectsAmbiguousUpstreamState(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "images", "firewall", "runtime", "inspect-firewall.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, expected := range []string{"count == 1", `print "ambiguous"`} {
		if !strings.Contains(text, expected) {
			t.Fatalf("gateway status script does not reject ambiguous upstream state with %q", expected)
		}
	}
}

func TestRemoteShellQuoteKeepsFirewallFiltersData(t *testing.T) {
	value := "HOME' ; id > /tmp/unexpected"
	quoted := remoteShellQuote(value)
	if quoted != "'HOME'\\'' ; id > /tmp/unexpected'" {
		t.Fatalf("remote shell quote = %q", quoted)
	}
}

func TestGatewayStatusScriptUsesReadOnlyTransport(t *testing.T) {
	if containsString(gatewayStatusScript, "sudo") {
		t.Fatal("read-only gateway status script unexpectedly requires sudo")
	}
}

func TestFirewallVerificationBindsTypedBackendToGuestKind(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("verification", "age1verification", model.GatewayModeManaged))
	config.Modules.Firewall = &model.FirewallModuleConfig{Backend: model.FirewallBackendLXC}
	s, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	backend, guest, err := firewallBackendForSite(s)
	if err != nil {
		t.Fatal(err)
	}
	if backend != model.FirewallBackendLXC || guest.Kind != proxmox.KindLXC || !guest.Security.Unprivileged {
		t.Fatalf("typed LXC backend resolved to %q/%#v", backend, guest)
	}

	s.ModuleConfig["firewall"] = model.ModuleConfig{Backend: model.FirewallBackendVM}
	if _, _, err := firewallBackendForSite(s); err == nil || !strings.Contains(err.Error(), "requires qemu guest") {
		t.Fatalf("backend/guest-kind mismatch was not rejected: %v", err)
	}
}

func TestFirewallStatusReportsSelectedBackend(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("status", "age1status", model.GatewayModeManaged))
	config.Modules.Firewall = &model.FirewallModuleConfig{Backend: model.FirewallBackendLXC}
	s, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := firewall.PlanFromSite(s)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := firewallStatus("", s, plan, false, false, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Backend     lxc") {
		t.Fatalf("firewall status omitted selected backend: %s", output.String())
	}
}

func containsString(value, wanted string) bool {
	for i := 0; i+len(wanted) <= len(value); i++ {
		if value[i:i+len(wanted)] == wanted {
			return true
		}
	}
	return false
}
