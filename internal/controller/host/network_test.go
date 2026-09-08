package host

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	"gopkg.in/yaml.v3"
)

func TestPrepareProtectedRangeChangeGatesAdoptionAndRetention(t *testing.T) {
	want := &ProtectedRanges{"10.10.10.224/28", "10.10.20.224/28", "10.10.30.224/28", "10.10.40.224/28"}
	for _, values := range []struct {
		name string
		obs  ProtectedRangeObservations
	}{
		{"reservation", ProtectedRangeObservations{Reservations: []string{"10.10.10.225"}}},
		{"lease", ProtectedRangeObservations{Leases: []string{"10.10.20.239"}}},
		{"managed", ProtectedRangeObservations{ManagedAttachments: []string{"10.10.40.224"}}},
	} {
		if err := PrepareProtectedRangeChange(nil, want, values.obs); err == nil {
			t.Errorf("occupied %s adoption accepted", values.name)
		}
	}
	if err := PrepareProtectedRangeChange(want, nil, ProtectedRangeObservations{}); err == nil {
		t.Fatal("release accepted")
	}
	changed := *want
	changed.Trusted = "10.10.30.240/28"
	if err := PrepareProtectedRangeChange(want, &changed, ProtectedRangeObservations{}); err == nil {
		t.Fatal("change accepted")
	}
	if err := PrepareProtectedRangeChange(want, want, ProtectedRangeObservations{Leases: []string{"10.10.20.225"}}); err != nil {
		t.Fatalf("unchanged adopted range rejected: %v", err)
	}
	for _, bad := range []string{"10.10.10.225/32", "2001:db8::1", "10.10.10.01"} {
		if err := PrepareProtectedRangeChange(nil, want, ProtectedRangeObservations{Reservations: []string{bad}}); err == nil {
			t.Errorf("malformed/occupied observation %q accepted", bad)
		}
	}
}

func TestLabYAMLStrictRoundTripPreservesVPNAndProtectedRanges(t *testing.T) {
	b := false
	want := LabConfig{Name: "lab", Proxmox: ProxmoxConfig{Address: "192.0.2.10", User: "root", Repository: "no-subscription"}, Network: &NetworkConfig{InternalBridge: "vmbr1", VLANs: VLANConfig{Transit: 5, Infra: 10, Servers: 20, Trusted: 30, Sandbox: 40, Mgmt: 99}, ProtectedRanges: &ProtectedRanges{"10.10.10.224/28", "10.10.20.224/28", "10.10.30.224/28", "10.10.40.224/28"}}, Modules: clientservices.Modules{DHCP: &clientservices.DHCPConfig{Reservations: []clientservices.Reservation{{Name: "peer", Zone: "TRUSTED", MAC: "02:00:00:00:30:61", Address: "10.10.30.225"}}}, VPN: &clientservices.VPNConfig{Enabled: &b, Clients: []string{"peer"}}}}
	data, err := yaml.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got LabConfig
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Network.ProtectedRanges == nil || got.Network.ProtectedRanges.Trusted != want.Network.ProtectedRanges.Trusted || got.Modules.VPN == nil || got.Modules.VPN.Clients[0] != "peer" {
		t.Fatalf("round trip lost intent: %#v", got)
	}
	var bad LabConfig
	decoder = yaml.NewDecoder(bytes.NewReader(append(data, []byte("unknown: true\n")...)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&bad); err == nil {
		t.Fatal("unknown YAML field accepted")
	}
}

const compatibleBridge = "auto vmbr1\niface vmbr1 inet manual\n bridge-ports none\n bridge-stp off\n bridge-fd 0\n bridge-vlan-aware yes\n bridge-vids 2-4094\niface vmbr1 inet6 manual\n"

func TestBridgeRejectsConfiguredAddressEvenWithoutRuntimeAddress(t *testing.T) {
	state := bridgeState([]ipLink{{IfName: "vmbr1", OperState: "UP"}}, nil, nil, "", "vlan_filtering 1", compatibleBridge+" address fe80::123/64\n")
	if state.Configured {
		t.Fatal("configured IPv6 address accepted as compatible")
	}
}

func TestBridgeLinkLocalAdoption(t *testing.T) {
	var addresses []ipAddress
	if err := json.Unmarshal([]byte(`[{"ifname":"vmbr1","addr_info":[{"family":"inet6","local":"fe80::123","scope":"link"}]}]`), &addresses); err != nil {
		t.Fatal(err)
	}
	state := bridgeState([]ipLink{{IfName: "vmbr1", OperState: "UP"}}, addresses, nil, "", "vlan_filtering 1", compatibleBridge)
	if state.Detail != "vmbr1 is compatible with explicit adoption and host-IPv6 suppression" {
		t.Fatalf("link-local classified as %q", state.Detail)
	}
}

func TestBridgeHealthRequiresLinkUp(t *testing.T) {
	state := bridgeState([]ipLink{{IfName: "vmbr1", OperState: "DOWN"}}, nil, nil, "", "vlan_filtering 1", compatibleBridge)
	if state.Up || state.Detail != "vmbr1 is not up" {
		t.Fatalf("down bridge state = %#v", state)
	}
}

func TestBridgeAdoptionRejectsConflicts(t *testing.T) {
	for _, tc := range []struct {
		name, address, config string
		member                bool
		route                 ipRoute
	}{
		{name: "IPv4", address: `{"family":"inet","local":"10.0.0.1","scope":"global"}`},
		{name: "global IPv6", address: `{"family":"inet6","local":"2001:db8::1","scope":"global"}`},
		{name: "wrong scope", address: `{"family":"inet6","local":"fe80::1","scope":"global"}`},
		{name: "invalid address", address: `{"family":"inet6","local":"bad","scope":"link"}`},
		{name: "physical member", member: true},
		{name: "IPv6 gateway", route: ipRoute{Dev: "vmbr1", Dst: "default", Gateway: "fe80::1"}},
		{name: "configured IPv4", config: " address 10.0.0.1/24\n"},
		{name: "configured gateway", config: " gateway 10.0.0.1\n"},
		{name: "unknown hook", config: " post-up echo unsafe\n"},
		{name: "duplicate stanza", config: "iface vmbr1 inet dhcp\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			links := []ipLink{{IfName: "vmbr1", OperState: "UP"}}
			if tc.member {
				links = append(links, ipLink{IfName: "nic1", Master: "vmbr1", LinkType: "ether"})
			}
			var addresses []ipAddress
			if tc.address != "" {
				if err := json.Unmarshal([]byte(`[{"ifname":"vmbr1","addr_info":[`+tc.address+`]}]`), &addresses); err != nil {
					t.Fatal(err)
				}
			}
			state := bridgeState(links, addresses, []ipRoute{tc.route}, "", "vlan_filtering 1", compatibleBridge+tc.config)
			if state.Adoptable {
				t.Fatalf("conflict accepted: %#v", state)
			}
		})
	}
}

func TestNetworkCommandRequiresExplicitAdoption(t *testing.T) {
	for _, state := range []string{"exact", "conflict", "adoptable"} {
		if _, err := NetworkConfigurationCommand(NetworkPlan{State: state}); err == nil {
			t.Fatalf("accepted %s without adoption", state)
		}
	}
	if _, err := NetworkConfigurationCommand(NetworkPlan{State: "conflict"}, true); err == nil {
		t.Fatal("adoption bypassed conflict")
	}
}

func TestNetworkDiscoveryRequiresPersistentAndLiveSuppression(t *testing.T) {
	for _, tc := range []struct {
		name, addr, owned, disabled, want string
		member                            bool
	}{
		{name: "unowned link local", addr: `{"family":"inet6","local":"fe80::123","scope":"link"}`, owned: "", disabled: "0", want: "adoptable"},
		{name: "unowned empty", addr: "", owned: "", disabled: "1", want: "adoptable"},
		{name: "owned enabled", addr: "", owned: "owned", disabled: "0", want: "adoptable"},
		{name: "exact", addr: "", owned: "owned", disabled: "1", want: "exact"},
		{name: "address remains", addr: `{"family":"inet6","local":"fe80::123","scope":"link"}`, owned: "owned", disabled: "1", want: "adoptable"},
		{name: "owned with attached port", addr: "", owned: "owned", disabled: "1", want: "exact", member: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			script := "#!/bin/sh\nfor arg; do command=$arg; done\ncase \"$command\" in\n"
			linkResponse := `[{"ifname":"vmbr0"},{"ifname":"nic0","master":"vmbr0"},{"ifname":"vmbr1","operstate":"UP"}]`
			if tc.member {
				linkResponse = `[{"ifname":"vmbr0"},{"ifname":"nic0","master":"vmbr0"},{"ifname":"nic1","master":"vmbr1"},{"ifname":"vmbr1","operstate":"UP"}]`
			}
			responses := map[string]string{
				"ip -json link":            linkResponse,
				"ip -json address":         `[{"ifname":"vmbr0","addr_info":[{"family":"inet","local":"192.168.4.5"}]},{"ifname":"vmbr1","addr_info":[` + tc.addr + `]}]`,
				"ip -json route":           `[{"dst":"default","gateway":"192.168.4.1","dev":"vmbr0"}]`,
				"ip route get 192.168.4.6": "192.168.4.6 dev vmbr0 src 192.168.4.5",
				"bridge link":              "", "ip -d link show vmbr1 2>/dev/null || true": "vlan_filtering 1",
				`set -eu; names=$(ifquery --list); if printf '%s\n' "$names" | grep -qx vmbr1; then ifquery --raw vmbr1; fi`:    compatibleBridge,
				`if [ -e /proc/sys/net/ipv6/conf/vmbr1/disable_ipv6 ]; then cat /proc/sys/net/ipv6/conf/vmbr1/disable_ipv6; fi`: tc.disabled,
				networkOwnershipCommand(): tc.owned, "ip -json -6 route": "[]",
			}
			for command, response := range responses {
				script += shellLiteral(command) + ") printf %s " + shellLiteral(response) + ";;\n"
			}
			script += "*) echo unexpected-command >&2; exit 99;;\nesac\n"
			ssh := filepath.Join(dir, "ssh")
			if err := os.WriteFile(ssh, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			config := LabConfig{Name: "lab", Proxmox: ProxmoxConfig{Address: "192.168.4.5", User: "root", Node: "pve", Repository: "no-subscription"}}
			plan, err := DiscoverNetwork(context.Background(), Transport{Address: "192.168.4.5", User: "root", Identity: filepath.Join(dir, "identity"), KnownHosts: filepath.Join(dir, "known_hosts"), SSHPath: ssh}, config)
			if err != nil {
				t.Fatal(err)
			}
			if plan.State != tc.want {
				t.Fatalf("state=%s want %s", plan.State, tc.want)
			}
		})
	}
}

func TestAdoptionCommandAndBootHook(t *testing.T) {
	dir := t.TempDir()
	for _, path := range []string{"etc/network/if-up.d", "etc/network/ifupdown2", "etc/sysctl.d", "proc/sys/net/ipv6/conf/vmbr1", "root", "bin"} {
		if err := os.MkdirAll(filepath.Join(dir, path), 0755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, content string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, path), []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	original := "auto vmbr0\niface vmbr0 inet static\n address 192.168.4.5/24\n" + compatibleBridge
	write("etc/network/interfaces", original, 0644)
	write("etc/network/ifupdown2/ifupdown2.conf", "addon_scripts_support=1\n", 0644)
	write("proc/sys/net/ipv6/conf/vmbr1/disable_ipv6", "0\n", 0644)
	write("bin/sysctl", "#!/bin/sh\n[ \"$*\" = '-q -w net.ipv6.conf.vmbr1.disable_ipv6=1' ] || exit 98\nprintf '1\\n' > "+shellLiteral(filepath.Join(dir, "proc/sys/net/ipv6/conf/vmbr1/disable_ipv6"))+"\n", 0755)
	command, err := NetworkConfigurationCommand(NetworkPlan{State: "adoptable"}, true)
	if err != nil {
		t.Fatal(err)
	}
	rewrite := strings.NewReplacer("/etc/", dir+"/etc/", "/root/", dir+"/root/", "/proc/", dir+"/proc/")
	run := func(script string, iface string) error {
		cmd := exec.Command("sh", "-c", rewrite.Replace(script))
		cmd.Env = append(os.Environ(), "PATH="+filepath.Join(dir, "bin")+":"+os.Getenv("PATH"), "IFACE="+iface)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("script output: %s", out)
		}
		return err
	}
	if err := run(command, ""); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "etc/network/interfaces"))
	if string(data) != original {
		t.Fatal("adoption changed interface configuration")
	}
	if err := run(networkOwnershipCommand(), ""); err != nil {
		t.Fatal(err)
	}
	write("proc/sys/net/ipv6/conf/vmbr1/disable_ipv6", "0\n", 0644)
	if err := run(bridgeHook, "vmbr0"); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(filepath.Join(dir, "proc/sys/net/ipv6/conf/vmbr1/disable_ipv6"))
	if string(data) != "0\n" {
		t.Fatal("hook affected HOME")
	}
	if err := run(bridgeHook, "vmbr1"); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(filepath.Join(dir, "proc/sys/net/ipv6/conf/vmbr1/disable_ipv6"))
	if string(data) != "1\n" {
		t.Fatal("hook failed to suppress IPv6")
	}
	write("etc/sysctl.d/70-boetticher-vmbr1.conf", "unowned\n", 0644)
	if err := run(command, ""); err == nil {
		t.Fatal("overwrote unowned setting")
	}
	path := filepath.Join(dir, "etc/sysctl.d/70-boetticher-vmbr1.conf")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "etc/network/interfaces"), path); err != nil {
		t.Fatal(err)
	}
	if err := run(command, ""); err == nil {
		t.Fatal("followed symlink")
	}
}
