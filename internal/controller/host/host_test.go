package host

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateHostKeyRequiresIPv4AndNormalizesKey(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA trusted"
	got, err := ValidateHostKey("192.0.2.10", key)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "192.0.2.10 ssh-ed25519 ") || strings.Contains(got, " trusted") {
		t.Fatalf("normalized host key = %q", got)
	}
	for _, address := range []string{"proxmox.example", "2001:db8::10", ""} {
		if _, err := ValidateHostKey(address, key); err == nil {
			t.Fatalf("ValidateHostKey(%q) unexpectedly passed", address)
		}
	}
}

func TestParseNodesAcceptsArrayAndDataEnvelope(t *testing.T) {
	for _, input := range []string{
		`[{"node":"pve","status":"online","type":"node"}]`,
		`{"data":[{"node":"pve","status":"online","type":"node"}]}`,
	} {
		nodes, err := parseNodes([]byte(input))
		if err != nil || len(nodes) != 1 || nodes[0].Node != "pve" {
			t.Fatalf("parseNodes(%s) = %#v, %v", input, nodes, err)
		}
	}
	if _, err := parseNodes([]byte(`{"not_nodes":true}`)); err == nil {
		t.Fatal("malformed node listing was accepted")
	}
}

func TestSupportedVersionRejectsUnknownMajor(t *testing.T) {
	for _, test := range []struct {
		version string
		want    bool
	}{
		{"pve-manager/9.2.2/b9984c6d90a4bd80", true},
		{"pve-manager/8.4.1/foo", true},
		{"pve-manager/7.4.17/foo", false},
		{"not-pve", false},
	} {
		if got := supportedVersion(test.version); got != test.want {
			t.Errorf("supportedVersion(%q) = %v, want %v", test.version, got, test.want)
		}
	}
}

func TestTransportArgsAreStrictAndRootOnly(t *testing.T) {
	transport := Transport{Address: "192.0.2.10", User: "root", Identity: PrivateKeyPath, KnownHosts: KnownHostsPath}
	args, err := transport.Args("hostname")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, required := range []string{"BatchMode=yes", "StrictHostKeyChecking=yes", "IdentitiesOnly=yes", "PasswordAuthentication=no", "KbdInteractiveAuthentication=no", "ControlMaster=no", "ControlPath=none", "ForwardAgent=no", "ForwardX11=no", "root@192.0.2.10", "hostname"} {
		if !strings.Contains(joined, required) {
			t.Errorf("transport args missing %q: %s", required, joined)
		}
	}
	if _, err := (Transport{Address: "192.0.2.10", User: "pi", Identity: PrivateKeyPath, KnownHosts: KnownHostsPath}).Args("hostname"); err == nil {
		t.Fatal("non-root transport was accepted")
	}
	if _, err := (Transport{Address: "192.0.2.10", User: "root", Identity: PrivateKeyPath, KnownHosts: KnownHostsPath}).Run(context.Background(), ""); err == nil {
		t.Fatal("empty remote command was accepted")
	}
}

func TestStorageDiscoveryHelpersTraceBootDiskAndStableIdentity(t *testing.T) {
	devices := []BlockDevice{{Name: "nvme0n1", Path: "/dev/nvme0n1", Type: "disk", Children: []BlockDevice{{Name: "nvme0n1p3", Path: "/dev/nvme0n1p3", Type: "part", PKName: "nvme0n1", Children: []BlockDevice{{Name: "pve-root", Path: "/dev/mapper/pve-root", Type: "lvm", PKName: "nvme0n1p3"}}}}}}
	boot := tracePhysicalDisk(devices, "/dev/mapper/pve-root")
	if boot.Path != "/dev/nvme0n1" {
		t.Fatalf("tracePhysicalDisk() = %#v, want nvme0n1", boot)
	}
	disk := Disk{BlockDevice: BlockDevice{Path: "/dev/sda"}}
	decorateDisk(&disk, stableIDMap("ata-Timetec -> /dev/sda\npartition -> /dev/sda1\n"))
	if len(disk.StableIDs) != 1 || disk.StableIDs[0] != "/dev/disk/by-id/ata-Timetec" {
		t.Fatalf("stable IDs = %#v", disk.StableIDs)
	}
}

func TestInitializationCommandUsesOnlyApprovedStableDiskAndFixedLayout(t *testing.T) {
	plan := StoragePlan{State: "empty", Selected: &Disk{BlockDevice: BlockDevice{Path: "/dev/sda", Model: "Timetec MS21", Serial: "SERIAL"}, StableIDs: []string{"/dev/disk/by-id/ata-Timetec_SERIAL"}}}
	command, err := InitializationCommand(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"device='/dev/disk/by-id/ata-Timetec_SERIAL'", "pvcreate", "vgcreate boetticher-vg", "lvcreate --yes -l 95%VG -T boetticher-vg/data", "pvesm add lvmthin boetticher-data", "--content images,rootdir", "lsblk -ndo MODEL", "Timetec MS21", "SERIAL"} {
		if !strings.Contains(command, required) {
			t.Errorf("initialization command missing %q: %s", required, command)
		}
	}
	for _, forbidden := range []string{"/dev/sda'", "--force", "--reinitialize", "mkfs", "mount ", "pvesm add dir"} {
		if strings.Contains(command, forbidden) {
			t.Errorf("initialization command contains forbidden %q: %s", forbidden, command)
		}
	}
}

func TestParseStorageAcceptsProxmoxEnvelope(t *testing.T) {
	data := json.RawMessage(`{"data":[{"storage":"boetticher-data","type":"lvmthin","active":1,"content":"images,rootdir"}]}`)
	storage := parseStorage(data)
	if len(storage) != 1 || storage[0].ID != "boetticher-data" || storage[0].Active != 1 {
		t.Fatalf("parseStorage() = %#v", storage)
	}
}

func TestClassifyExistingLayoutRequiresAllOwnedLayers(t *testing.T) {
	plan := StoragePlan{
		Selected: &Disk{BlockDevice: BlockDevice{Path: "/dev/sda"}},
		PVJSON:   json.RawMessage(`{"pv_name":"/dev/sda","vg_name":"boetticher-vg"}`),
		VGJSON:   json.RawMessage(`{"vg_name":"boetticher-vg"}`),
		LVJSON:   json.RawMessage(`{"lv_name":"data"}`),
		Proxmox:  json.RawMessage(`{"storage":"boetticher-data","type":"lvmthin","vgname":"boetticher-vg","thinpool":"data"}`),
	}
	state, _ := classifyExistingLayout(plan, StorageConfig{Profile: StorageProfile, Device: "/dev/disk/by-id/ata-example", GuestStorage: GuestStorageID})
	if state != "exact" {
		t.Fatalf("classifyExistingLayout() = %q, want exact", state)
	}
	plan.LVJSON = json.RawMessage(`{"lv_name":"other"}`)
	state, _ = classifyExistingLayout(plan, StorageConfig{Profile: StorageProfile, Device: "/dev/disk/by-id/ata-example", GuestStorage: GuestStorageID})
	if state != "conflict" {
		t.Fatalf("partial layout classified as %q, want conflict", state)
	}
}

func TestExactOwnedStorageCanRecoverSelectionWithoutMutation(t *testing.T) {
	plan := StoragePlan{
		PVJSON:  json.RawMessage(`{"report":[{"pv":[{"pv_name":"/dev/sda","vg_name":"boetticher-vg"}]}]}`),
		VGJSON:  json.RawMessage(`{"report":[{"vg":[{"vg_name":"boetticher-vg"}]}]}`),
		LVJSON:  json.RawMessage(`{"report":[{"lv":[{"lv_name":"data"}]}]}`),
		Proxmox: json.RawMessage(`[{"storage":"boetticher-data","type":"lvmthin","vgname":"boetticher-vg","thinpool":"data"}]`),
	}
	if !exactOwnedStorage(plan) || pvPathForVG(plan.PVJSON, StorageVolumeGroup) != "/dev/sda" {
		t.Fatal("exact owned storage was not recognized")
	}
}

func TestValidateNetworkConfigRequiresFixedVLANTopology(t *testing.T) {
	config := DefaultNetworkConfig()
	if err := ValidateNetworkConfig(config); err != nil {
		t.Fatal(err)
	}
	config.InternalBridge = "vmbr9"
	if err := ValidateNetworkConfig(config); err == nil {
		t.Fatal("arbitrary internal bridge was accepted")
	}
	config = DefaultNetworkConfig()
	config.VLANs.Mgmt = config.VLANs.Servers
	if err := ValidateNetworkConfig(config); err == nil {
		t.Fatal("duplicate VLAN IDs were accepted")
	}
}

func TestBridgeStateRecognizesExactVirtualOnlyBridge(t *testing.T) {
	state := bridgeState(
		[]ipLink{{IfName: "vmbr1", LinkType: "bridge"}},
		[]ipAddress{{IfName: "vmbr1"}},
		[]ipRoute{},
		"",
		"vmbr1: vlan_filtering 1",
		"auto vmbr1\niface vmbr1 inet manual\n\tbridge-ports none\n\tbridge-vlan-aware yes\n\tbridge-vids 2-4094\n",
	)
	if !state.Exists || !state.VLANAware || !state.Configured || len(state.HostAddresses) != 0 || len(state.PhysicalMembers) != 0 {
		t.Fatalf("exact bridge state = %#v", state)
	}
}
