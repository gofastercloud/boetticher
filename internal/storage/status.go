package storage

import (
	"errors"
	"fmt"
	"strings"
)

// LiveStatus is the small read-only storage evidence contract used by doctor.
// It intentionally reports only the fixed dedicated-data-disk layout.
type LiveStatus struct {
	Device        string `json:"device"`
	DevicePath    string `json:"device_path"`
	VolumeGroup   string `json:"volume_group"`
	ThinPool      string `json:"thin_pool"`
	BackupLV      string `json:"backup_lv"`
	Filesystem    string `json:"filesystem"`
	Mount         string `json:"mount"`
	GuestStorage  string `json:"guest_storage"`
	BackupStorage string `json:"backup_storage"`
	Capacity      string `json:"capacity,omitempty"`
}

// StatusCommand is a fixed, read-only command. The configured device is the
// only installation value interpolated, and it has already passed the stable
// by-id validation in the site model and storage planner.
func StatusCommand(device string) (string, error) {
	if err := validateDevice(device); err != nil {
		return "", err
	}
	quoted := shellQuote(device)
	return strings.Join([]string{
		"set -u",
		"device=" + quoted,
		"printf 'device=%s\\n' \"$device\"",
		"device_path=\"$(readlink -f \"$device\" 2>/dev/null || true)\"",
		"printf 'device_path=%s\\n' \"${device_path:-missing}\"",
		"volume_group=\"$(vgs --noheadings --select vg_name=" + VolumeGroup + " -o vg_name 2>/dev/null | xargs)\"",
		"printf 'volume_group=%s\\n' \"${volume_group:-missing}\"",
		"thin_pool=\"$(lvs --noheadings --select lv_name=" + ThinPool + " -o lv_name " + VolumeGroup + " 2>/dev/null | xargs)\"",
		"printf 'thin_pool=%s\\n' \"${thin_pool:-missing}\"",
		"backup_lv=\"$(lvs --noheadings --select lv_name=" + BackupLogicalVol + " -o lv_name " + VolumeGroup + " 2>/dev/null | xargs)\"",
		"printf 'backup_lv=%s\\n' \"${backup_lv:-missing}\"",
		"filesystem=\"$(blkid -s TYPE -o value /dev/" + VolumeGroup + "/" + BackupLogicalVol + " 2>/dev/null || true)\"",
		"printf 'filesystem=%s\\n' \"${filesystem:-missing}\"",
		"mount=\"$(findmnt -no TARGET /dev/" + VolumeGroup + "/" + BackupLogicalVol + " 2>/dev/null || true)\"",
		"printf 'mount=%s\\n' \"${mount:-missing}\"",
		"printf 'guest_storage=%s\\n' \"$(pvesm status --storage " + GuestStorageID + " >/dev/null 2>&1 && printf active || printf missing)\"",
		"printf 'backup_storage=%s\\n' \"$(pvesm status --storage " + BackupStorageID + " >/dev/null 2>&1 && printf active || printf missing)\"",
		"capacity=\"$(df -hP " + BackupMount + " 2>/dev/null | tail -n 1 | xargs)\"",
		"printf 'capacity=%s\\n' \"${capacity:-unavailable}\"",
	}, "\n"), nil
}

func ParseStatus(output string) (LiveStatus, error) {
	status := LiveStatus{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || value == "" {
			return LiveStatus{}, fmt.Errorf("storage status contains malformed line %q", line)
		}
		switch key {
		case "device":
			status.Device = value
		case "device_path":
			status.DevicePath = value
		case "volume_group":
			status.VolumeGroup = value
		case "thin_pool":
			status.ThinPool = value
		case "backup_lv":
			status.BackupLV = value
		case "filesystem":
			status.Filesystem = value
		case "mount":
			status.Mount = value
		case "guest_storage":
			status.GuestStorage = value
		case "backup_storage":
			status.BackupStorage = value
		case "capacity":
			status.Capacity = value
		default:
			return LiveStatus{}, fmt.Errorf("storage status contains unknown field %q", key)
		}
	}
	if status.Device == "" || status.DevicePath == "" || status.VolumeGroup == "" || status.ThinPool == "" || status.BackupLV == "" || status.Filesystem == "" || status.Mount == "" || status.GuestStorage == "" || status.BackupStorage == "" {
		return LiveStatus{}, errors.New("storage status is incomplete")
	}
	return status, nil
}
