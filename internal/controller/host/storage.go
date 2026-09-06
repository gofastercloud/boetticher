package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
)

const (
	StorageProfile     = "dedicated-data-disk"
	GuestStorageID     = "boetticher-data"
	StorageVolumeGroup = "boetticher-vg"
	StorageThinPool    = "data"
)

type BlockDevice struct {
	Name        string        `json:"name"`
	Path        string        `json:"path"`
	Type        string        `json:"type"`
	Size        uint64        `json:"size"`
	Model       string        `json:"model"`
	Serial      string        `json:"serial"`
	WWN         string        `json:"wwn"`
	FSType      string        `json:"fstype"`
	Mountpoints []string      `json:"mountpoints"`
	PKName      string        `json:"pkname"`
	Children    []BlockDevice `json:"children"`
}

type Disk struct {
	BlockDevice
	StableIDs []string
}

type StoragePlan struct {
	EnrolledNode string
	BootDisk     Disk
	Candidates   []Disk
	Selected     *Disk
	State        string
	Detail       string
	PVJSON       json.RawMessage
	VGJSON       json.RawMessage
	LVJSON       json.RawMessage
	Proxmox      json.RawMessage
	Guests       json.RawMessage
	Mounts       json.RawMessage
}

func DiscoverStorage(ctx context.Context, transport Transport, config LabConfig) (StoragePlan, error) {
	if _, err := ValidateConfigForStorage(config); err != nil {
		return StoragePlan{}, err
	}
	lsblk, err := transport.Run(ctx, "lsblk --json --bytes --output NAME,PATH,TYPE,SIZE,MODEL,SERIAL,WWN,FSTYPE,MOUNTPOINTS,PKNAME")
	if err != nil {
		return StoragePlan{}, fmt.Errorf("read block devices: %w", err)
	}
	var listing struct {
		BlockDevices []BlockDevice `json:"blockdevices"`
	}
	if err := json.Unmarshal(lsblk.Stdout, &listing); err != nil {
		return StoragePlan{}, fmt.Errorf("decode block devices: %w", err)
	}
	byIDResult, err := transport.Run(ctx, "for path in /dev/disk/by-id/*; do [ -L \"$path\" ] && printf '%s -> %s\\n' \"${path##*/}\" \"$(readlink -f \"$path\")\"; done")
	if err != nil {
		return StoragePlan{}, fmt.Errorf("read stable disk identities: %w", err)
	}
	ids := stableIDMap(string(byIDResult.Stdout))
	rootResult, err := transport.Run(ctx, "findmnt --json")
	if err != nil {
		return StoragePlan{}, fmt.Errorf("read mounts: %w", err)
	}
	var mounts map[string]any
	if err := json.Unmarshal(rootResult.Stdout, &mounts); err != nil {
		return StoragePlan{}, fmt.Errorf("decode mounts: %w", err)
	}
	rootSource := findMountSource(mounts, "/")
	bootDisk := tracePhysicalDisk(listing.BlockDevices, rootSource)
	if bootDisk.Path == "" {
		return StoragePlan{}, errors.New("could not trace the running root filesystem to a physical boot disk")
	}
	decorateDisk(&bootDisk, ids)
	allDisks := make([]Disk, 0)
	for _, device := range listing.BlockDevices {
		if device.Type != "disk" || device.Size == 0 {
			continue
		}
		disk := Disk{BlockDevice: device}
		decorateDisk(&disk, ids)
		allDisks = append(allDisks, disk)
	}
	pv, err := transport.Run(ctx, "pvs --reportformat json")
	if err != nil {
		return StoragePlan{}, fmt.Errorf("read LVM physical volumes: %w", err)
	}
	vg, err := transport.Run(ctx, "vgs --reportformat json")
	if err != nil {
		return StoragePlan{}, fmt.Errorf("read LVM volume groups: %w", err)
	}
	lv, err := transport.Run(ctx, "lvs --reportformat json")
	if err != nil {
		return StoragePlan{}, fmt.Errorf("read LVM logical volumes: %w", err)
	}
	proxmox, err := transport.Run(ctx, "pvesh get /storage --output-format json")
	if err != nil {
		return StoragePlan{}, fmt.Errorf("read Proxmox storage: %w", err)
	}
	guests, err := transport.Run(ctx, "pvesh get /cluster/resources --type vm --output-format json")
	if err != nil {
		return StoragePlan{}, fmt.Errorf("read Proxmox guests: %w", err)
	}
	plan := StoragePlan{EnrolledNode: config.Proxmox.Node, BootDisk: bootDisk, PVJSON: pv.Stdout, VGJSON: vg.Stdout, LVJSON: lv.Stdout, Proxmox: proxmox.Stdout, Guests: guests.Stdout, Mounts: rootResult.Stdout}
	protected := map[string]bool{bootDisk.Path: true}
	for _, source := range mountSources(mounts) {
		if disk := tracePhysicalDisk(listing.BlockDevices, source); disk.Path != "" {
			protected[disk.Path] = true
		}
	}
	for _, disk := range allDisks {
		if protected[disk.Path] || sameDisk(disk, bootDisk) {
			continue
		}
		if len(disk.StableIDs) == 0 || diskHasMountOrChildren(disk) || disk.FSType != "" {
			continue
		}
		plan.Candidates = append(plan.Candidates, disk)
	}
	if config.Storage != nil {
		for _, disk := range allDisks {
			if containsString(disk.StableIDs, config.Storage.Device) {
				plan.Selected = &disk
				break
			}
		}
		plan.State, plan.Detail = classifyExistingLayout(plan, *config.Storage)
	} else if exactOwnedStorage(plan) {
		pvPath := pvPathForVG(plan.PVJSON, StorageVolumeGroup)
		for _, disk := range allDisks {
			if disk.Path == pvPath {
				plan.Selected = &disk
				break
			}
		}
		if plan.Selected != nil {
			plan.State = "exact"
			plan.Detail = "exact Boetticher LVM-thin layout is already present; controller selection can be recorded without mutation"
		} else {
			plan.State = "conflict"
			plan.Detail = "boetticher-data exists but its PV cannot be mapped to a stable disk"
		}
	} else if bytesContain(plan.Proxmox, []byte(`"storage":"`+GuestStorageID+`"`)) {
		plan.State = "conflict"
		plan.Detail = "boetticher-data already exists without a matching controller selection"
	} else if len(plan.Candidates) == 1 {
		plan.Selected = &plan.Candidates[0]
		plan.State = "empty"
		plan.Detail = "one unused whole-disk candidate discovered"
	} else if len(plan.Candidates) > 1 {
		plan.State = "ambiguous"
		plan.Detail = fmt.Sprintf("%d unused whole-disk candidates require explicit selection", len(plan.Candidates))
	} else {
		plan.State = "none"
		plan.Detail = "no unused whole-disk candidate is safe to initialize"
	}
	return plan, nil
}

func ValidateConfigForStorage(config LabConfig) (LabConfig, error) {
	if err := ValidateConfig(config); err != nil {
		return LabConfig{}, err
	}
	if net.ParseIP(config.Proxmox.Address) == nil {
		return LabConfig{}, errors.New("storage requires an enrolled IPv4 Proxmox host")
	}
	return config, nil
}

func stableIDMap(output string) map[string]string {
	result := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), " -> ", 2)
		if len(parts) == 2 && strings.HasPrefix(parts[1], "/dev/") {
			result[parts[0]] = parts[1]
		}
	}
	return result
}

func decorateDisk(disk *Disk, ids map[string]string) {
	for id, target := range ids {
		if target == disk.Path {
			disk.StableIDs = append(disk.StableIDs, "/dev/disk/by-id/"+id)
		}
	}
	sort.Strings(disk.StableIDs)
}

func sameDisk(left, right Disk) bool { return left.Path != "" && left.Path == right.Path }

func diskHasMountOrChildren(disk Disk) bool {
	if len(disk.Mountpoints) > 0 {
		for _, mount := range disk.Mountpoints {
			if strings.TrimSpace(mount) != "" {
				return true
			}
		}
	}
	return len(disk.Children) > 0
}

func tracePhysicalDisk(devices []BlockDevice, source string) Disk {
	name := strings.TrimPrefix(source, "/dev/mapper/")
	name = strings.TrimPrefix(name, "/dev/")
	for _, device := range devices {
		if disk := traceDevice(device, name); disk.Path != "" {
			return disk
		}
	}
	return Disk{}
}

func traceDevice(device BlockDevice, name string) Disk {
	if device.Name == name || strings.TrimPrefix(device.Path, "/dev/") == name {
		if device.Type == "disk" {
			return Disk{BlockDevice: device}
		}
		if device.PKName != "" {
			return Disk{BlockDevice: BlockDevice{Name: device.PKName, Path: "/dev/" + device.PKName}}
		}
	}
	for _, child := range device.Children {
		if disk := traceDevice(child, name); disk.Path != "" {
			if disk.Type == "" && device.Type == "disk" {
				return Disk{BlockDevice: device}
			}
			return disk
		}
	}
	return Disk{}
}

func findMountSource(value any, target string) string {
	switch item := value.(type) {
	case map[string]any:
		if item["target"] == target {
			if source, ok := item["source"].(string); ok {
				return source
			}
		}
		for _, child := range item {
			if source := findMountSource(child, target); source != "" {
				return source
			}
		}
	case []any:
		for _, child := range item {
			if source := findMountSource(child, target); source != "" {
				return source
			}
		}
	}
	return ""
}

func mountSources(value any) []string {
	sources := make([]string, 0)
	switch item := value.(type) {
	case map[string]any:
		if source, ok := item["source"].(string); ok && strings.HasPrefix(source, "/dev/") {
			sources = append(sources, source)
		}
		for _, child := range item {
			sources = append(sources, mountSources(child)...)
		}
	case []any:
		for _, child := range item {
			sources = append(sources, mountSources(child)...)
		}
	}
	return sources
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func classifyExistingLayout(plan StoragePlan, config StorageConfig) (string, string) {
	if plan.Selected == nil {
		return "conflict", "configured stable disk identity is not present"
	}
	if len(plan.Selected.Children) > 0 && plan.Selected.FSType == "" {
		return "conflict", "configured disk has unexpected partitions or child devices"
	}
	if bytesContain(plan.PVJSON, []byte(`"pv_name":"`+plan.Selected.Path+`"`)) && bytesContain(plan.PVJSON, []byte(`"vg_name":"`+StorageVolumeGroup+`"`)) && bytesContain(plan.VGJSON, []byte(`"vg_name":"`+StorageVolumeGroup+`"`)) && bytesContain(plan.LVJSON, []byte(`"lv_name":"`+StorageThinPool+`"`)) && bytesContain(plan.Proxmox, []byte(`"storage":"`+config.GuestStorage+`"`)) && bytesContain(plan.Proxmox, []byte(`"type":"lvmthin"`)) && bytesContain(plan.Proxmox, []byte(`"vgname":"`+StorageVolumeGroup+`"`)) && bytesContain(plan.Proxmox, []byte(`"thinpool":"`+StorageThinPool+`"`)) {
		return "exact", "exact Boetticher LVM-thin layout is already present"
	}
	if bytesContain(plan.PVJSON, []byte(StorageVolumeGroup)) || bytesContain(plan.VGJSON, []byte(StorageVolumeGroup)) || bytesContain(plan.Proxmox, []byte(config.GuestStorage)) {
		return "conflict", "partial or conflicting Boetticher storage state requires review"
	}
	if len(plan.Selected.Children) == 0 && plan.Selected.FSType == "" && len(plan.Selected.Mountpoints) == 0 {
		return "empty", "configured stable disk is empty and eligible for initialization"
	}
	return "conflict", "configured disk is not an empty candidate"
}

func bytesContain(data []byte, needle []byte) bool {
	return strings.Contains(string(data), string(needle))
}

func exactOwnedStorage(plan StoragePlan) bool {
	return bytesContain(plan.PVJSON, []byte(`"vg_name":"`+StorageVolumeGroup+`"`)) && bytesContain(plan.VGJSON, []byte(`"vg_name":"`+StorageVolumeGroup+`"`)) && bytesContain(plan.LVJSON, []byte(`"lv_name":"`+StorageThinPool+`"`)) && bytesContain(plan.Proxmox, []byte(`"storage":"`+GuestStorageID+`"`)) && bytesContain(plan.Proxmox, []byte(`"type":"lvmthin"`)) && bytesContain(plan.Proxmox, []byte(`"vgname":"`+StorageVolumeGroup+`"`)) && bytesContain(plan.Proxmox, []byte(`"thinpool":"`+StorageThinPool+`"`))
}

// StorageTeardownState identifies only the native states that the bounded
// teardown operation can safely handle. It deliberately does not infer or
// repair an unknown disk layout.
func StorageTeardownState(plan StoragePlan) (string, string) {
	if len(parseGuests(plan.Guests)) != 0 {
		return "conflict", "boetticher-data contains guest state"
	}
	if plan.Selected == nil || len(plan.Selected.StableIDs) == 0 {
		return "conflict", "configured Timetec disk does not have a stable identity"
	}
	hasPV := bytesContain(plan.PVJSON, []byte(`"pv_name":"`+plan.Selected.Path+`"`)) && bytesContain(plan.PVJSON, []byte(`"vg_name":"`+StorageVolumeGroup+`"`))
	hasVG := bytesContain(plan.VGJSON, []byte(`"vg_name":"`+StorageVolumeGroup+`"`))
	hasLV := bytesContain(plan.LVJSON, []byte(`"lv_name":"`+StorageThinPool+`"`))
	hasStorage := bytesContain(plan.Proxmox, []byte(`"storage":"`+GuestStorageID+`"`))
	if !hasPV && !hasVG && !hasLV && !hasStorage {
		if len(plan.Selected.Children) == 0 && plan.Selected.FSType == "" && len(plan.Selected.Mountpoints) == 0 {
			return "absent", "the configured Timetec disk is already empty"
		}
		return "conflict", "the configured Timetec disk has an unknown native layout"
	}
	if (hasPV && !hasVG) || (hasVG && !hasLV) || (hasLV && !hasVG) {
		return "owned-partial", "a partial Boetticher LVM layout can be removed after native revalidation"
	}
	return "owned", "exact Boetticher storage or a recognized partial layout is present"
}

func pvPathForVG(data []byte, wantVG string) string {
	var document struct {
		Report []struct {
			PV []struct {
				Name string `json:"pv_name"`
				VG   string `json:"vg_name"`
			} `json:"pv"`
		} `json:"report"`
	}
	if json.Unmarshal(data, &document) != nil {
		return ""
	}
	for _, report := range document.Report {
		for _, pv := range report.PV {
			if pv.VG == wantVG {
				return pv.Name
			}
		}
	}
	return ""
}

func InitializationCommand(plan StoragePlan) (string, error) {
	if plan.Selected == nil || len(plan.Selected.StableIDs) == 0 {
		return "", errors.New("no uniquely identified stable data disk is selected")
	}
	if plan.State != "empty" {
		return "", fmt.Errorf("storage state %s is not eligible for first initialization: %s", plan.State, plan.Detail)
	}
	device := plan.Selected.StableIDs[0]
	if strings.ContainsAny(device, "'\n\r\\") || !strings.HasPrefix(device, "/dev/disk/by-id/") {
		return "", errors.New("selected storage identity is invalid")
	}
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
	lines := []string{
		"set -eu",
		"device=" + quote(device),
		"test -e \"$device\"",
		"resolved=\"$(readlink -f \"$device\")\"",
		"test -b \"$resolved\"",
		"test \"$(lsblk -ndo TYPE \"$resolved\")\" = disk",
		"test \"$(lsblk -nro NAME \"$resolved\" | wc -l | tr -d ' ')\" = 1",
		"test -z \"$(lsblk -nrpo MOUNTPOINTS \"$resolved\" | awk 'NF { print; exit }')\"",
		"root=\"$(readlink -f \"$(findmnt -no SOURCE /)\")\"",
		"while parent=\"$(lsblk -ndo PKNAME \"$root\")\"; do [ -n \"$parent\" ] || break; root=\"/dev/$parent\"; done",
		"test \"$resolved\" != \"$root\"",
		"pvesh get /nodes --output-format json | grep -Fq " + quote(`"node":"`+plan.EnrolledNode+`"`),
		"if swapon --noheadings --raw --output NAME 2>/dev/null | grep -Fqx \"$resolved\"; then echo 'refusing an active swap disk' >&2; exit 51; fi",
		"test -z \"$(pvs --noheadings -o pv_name 2>/dev/null | grep -F \"$resolved\" || true)\"",
		"if grep -R -Fq \"$resolved\" /etc/pve/qemu-server /etc/pve/lxc 2>/dev/null; then echo 'refusing a disk referenced by a guest' >&2; exit 52; fi",
		"if grep -Fq 'boetticher-data' /etc/pve/storage.cfg 2>/dev/null; then echo 'refusing an existing boetticher-data storage definition' >&2; exit 53; fi",
		"test -z \"$(wipefs -n \"$resolved\")\"",
	}
	if plan.Selected.Model != "" {
		lines = append(lines, "test \"$(lsblk -ndo MODEL \"$resolved\")\" = "+quote(strings.TrimSpace(plan.Selected.Model)))
	}
	if plan.Selected.Serial != "" {
		lines = append(lines, "test \"$(lsblk -ndo SERIAL \"$resolved\")\" = "+quote(strings.TrimSpace(plan.Selected.Serial)))
	}
	if plan.Selected.WWN != "" {
		lines = append(lines, "test \"$(lsblk -ndo WWN \"$resolved\")\" = "+quote(strings.TrimSpace(plan.Selected.WWN)))
	}
	lines = append(lines,
		"pvcreate --yes \"$resolved\"",
		"vgcreate boetticher-vg \"$resolved\"",
		"lvcreate --yes -l 95%VG -T boetticher-vg/data",
		"pvesm add lvmthin boetticher-data --vgname boetticher-vg --thinpool data --content images,rootdir",
		"lvs --noheadings -o lv_attr boetticher-vg/data | grep -Eq '^[[:space:]]*t'",
		"pvesm status --storage boetticher-data",
	)
	return strings.Join(lines, "; "), nil
}

// StorageTeardownCommand removes only the exact Boetticher LVM-thin layout on
// the freshly resolved configured whole disk. Registration is removed before
// the LVM layers; unrelated storage, mounts, swaps, guests, and the boot disk
// are refused by the native checks.
func StorageTeardownCommand(plan StoragePlan, confirmDevice string) (string, error) {
	if plan.Selected == nil || !containsString(plan.Selected.StableIDs, confirmDevice) {
		return "", errors.New("teardown confirmation must match the one configured stable Timetec disk identity")
	}
	state, detail := StorageTeardownState(plan)
	if state != "owned" && state != "owned-partial" && state != "absent" {
		return "", fmt.Errorf("storage state %s is not eligible for teardown: %s", state, detail)
	}
	device := confirmDevice
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
	lines := []string{
		"set -eu",
		"device=" + quote(device),
		"test -e \"$device\"",
		"resolved=\"$(readlink -f \"$device\")\"",
		"test -b \"$resolved\"",
		"test \"$(lsblk -ndo TYPE \"$resolved\")\" = disk",
		"if lsblk -nrpo TYPE \"$resolved\" | grep -qx part; then echo 'refusing the selected disk because it has a partition' >&2; exit 54; fi",
		"test -z \"$(lsblk -nrpo MOUNTPOINTS \"$resolved\" | awk 'NF { print; exit }')\"",
		"root=\"$(readlink -f \"$(findmnt -no SOURCE /)\")\"",
		"while parent=\"$(lsblk -ndo PKNAME \"$root\")\"; do [ -n \"$parent\" ] || break; root=\"/dev/$parent\"; done",
		"test \"$resolved\" != \"$root\"",
		"if swapon --noheadings --raw --output NAME 2>/dev/null | grep -Fqx \"$resolved\"; then echo 'refusing an active swap disk' >&2; exit 51; fi",
		"if grep -R -Fq \"$resolved\" /etc/pve/qemu-server /etc/pve/lxc 2>/dev/null; then echo 'refusing a disk referenced by a guest' >&2; exit 52; fi",
		"storage_json=\"$(pvesh get /storage/boetticher-data --output-format json 2>/dev/null || true)\"; storage_owned=0; if [ -n \"$storage_json\" ]; then printf %s \"$storage_json\" | grep -Fq '\"type\":\"lvmthin\"' && printf %s \"$storage_json\" | grep -Fq '\"vgname\":\"boetticher-vg\"' && printf %s \"$storage_json\" | grep -Fq '\"thinpool\":\"data\"' || { echo 'refusing a conflicting boetticher-data storage definition' >&2; exit 53; }; storage_owned=1; fi",
		"if pvs --noheadings --separator=: -o pv_name,vg_name 2>/dev/null | awk -F: -v p=\"$resolved\" '$1 ~ p && $2 !~ /boetticher-vg/ { bad=1 } END { exit(bad ? 1 : 0) }'; then :; else echo 'refusing the selected disk because its PV is not Boetticher-owned' >&2; exit 54; fi",
		"if lvs --noheadings --separator=: -o lv_name,vg_name 2>/dev/null | sed 's/[[:space:]]//g' | awk -F: '$2 == \"boetticher-vg\" && $1 != \"data\" { bad=1 } END { exit(bad ? 1 : 0) }'; then :; else echo 'refusing an unexpected logical volume in boetticher-vg' >&2; exit 56; fi",
		"pv_owned=0; if pvs --noheadings --separator=: -o pv_name,vg_name 2>/dev/null | awk -F: -v p=\"$resolved\" '$1 ~ p && $2 ~ /boetticher-vg/ { found++ } END { exit(found == 1 ? 0 : 1) }'; then pv_owned=1; fi",
		"vg_owned=0; if vgs --noheadings --separator=: -o vg_name 2>/dev/null | sed 's/[[:space:]]//g' | grep -qx 'boetticher-vg'; then vg_owned=1; fi",
		"lv_owned=0; if lvs --noheadings --separator=: -o lv_name,vg_name 2>/dev/null | sed 's/[[:space:]]//g' | grep -qx 'data:boetticher-vg'; then lv_owned=1; fi",
		"if [ \"$storage_owned\" = 1 ]; then pvesm remove boetticher-data; fi",
		"if [ \"$lv_owned\" = 1 ]; then lvremove --yes boetticher-vg/data; fi",
		"if [ \"$vg_owned\" = 1 ]; then vgremove --yes boetticher-vg; fi",
		"if [ \"$pv_owned\" = 1 ]; then pvremove --yes --force --force \"$resolved\"; fi",
		"wipefs --all \"$resolved\"",
		"test -z \"$(wipefs -n \"$resolved\")\"",
	}
	return strings.Join(lines, "; "), nil
}
