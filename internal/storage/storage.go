package storage

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
)

const (
	VolumeGroup      = "vg_boetticher"
	ThinPool         = "thinpool"
	BackupLogicalVol = "backup"
	BackupMount      = "/srv/boetticher/backups"
	BackupFilesystem = "ext4"
	GuestStorageID   = "boetticher-thin"
	BackupStorageID  = "boetticher-backups"
	ThinPoolPercent  = "70%VG"
	BackupLVPercent  = "20%VG"
)

// LocalStorageContent is the fixed content contract for Proxmox's built-in
// directory storage. Dedicated data storage owns backups separately, so local
// backup content is required only by the single-disk profile.
func LocalStorageContent(profile string) ([]string, error) {
	switch profile {
	case "single-disk":
		return []string{"backup", "images", "rootdir", "snippets", "vztmpl"}, nil
	case "dedicated-data-disk":
		return []string{"images", "rootdir", "snippets", "vztmpl"}, nil
	default:
		return nil, fmt.Errorf("unsupported storage profile %q", profile)
	}
}

// Plan is the complete, fixed 0.4 storage contract. It describes only
// boetticher-owned storage and deliberately has no knobs for arbitrary LVM
// layouts or additional storage backends.
type Plan struct {
	ModelRevision string           `json:"model_revision"`
	Profile       string           `json:"profile"`
	Device        string           `json:"device,omitempty"`
	VolumeGroup   string           `json:"volume_group,omitempty"`
	ThinPool      string           `json:"thin_pool,omitempty"`
	BackupLV      string           `json:"backup_lv,omitempty"`
	BackupMount   string           `json:"backup_mount"`
	Filesystem    string           `json:"filesystem"`
	GuestStorage  string           `json:"guest_storage"`
	BackupStorage string           `json:"backup_storage"`
	Volumes       []ResolvedVolume `json:"volumes,omitempty"`
}

type ResolvedVolume struct {
	Module    string                 `json:"module"`
	Name      string                 `json:"name"`
	Guest     string                 `json:"guest"`
	Storage   string                 `json:"storage"`
	Placement model.StoragePlacement `json:"placement"`
	Backup    bool                   `json:"backup"`
}

func PlanFromSite(s model.Site) (Plan, error) {
	if err := s.Validate(); err != nil {
		return Plan{}, err
	}
	revision, err := s.Revision()
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{
		ModelRevision: revision,
		Profile:       s.StorageProfile,
		BackupMount:   "/var/lib/vz/dump",
		Filesystem:    "directory-backed",
		GuestStorage:  "local",
		BackupStorage: "local",
	}
	if s.StorageProfile == "dedicated-data-disk" {
		plan.Device = s.StorageDevice
		plan.VolumeGroup = VolumeGroup
		plan.ThinPool = ThinPool
		plan.BackupLV = BackupLogicalVol
		plan.BackupMount = BackupMount
		plan.Filesystem = BackupFilesystem
		plan.GuestStorage = GuestStorageID
		plan.BackupStorage = BackupStorageID
	}
	declarations := make([]model.PersistentVolumeDeclaration, 0)
	for _, declaration := range s.Declarations {
		declarations = append(declarations, declaration.Volumes...)
	}
	// Portal is a Core-owned appliance, not a module, but its endpoint identity
	// still follows the same independent-volume replacement contract.
	for _, component := range s.PlatformComponents() {
		if component.Name == "lab-portal-01" {
			declarations = append(declarations, model.PersistentVolumeDeclaration{
				Name: "ssh-identity", Module: "portal", Guest: component.Name,
				SizeGiB: 1, MountPath: "/var/lib/boetticher/identity/ssh",
				Placement: model.StorageDefault, Backup: true,
			})
		}
	}
	for _, volume := range declarations {
		selected := plan.GuestStorage
		switch volume.Placement {
		case model.StoragePreferDataDisk, model.StorageRequireDataDisk:
			if s.StorageProfile == "dedicated-data-disk" {
				selected = GuestStorageID
			} else if volume.Placement == model.StorageRequireDataDisk {
				return Plan{}, fmt.Errorf("HOLD: module %s volume %s requires dedicated boetticher data storage", volume.Module, volume.Name)
			}
		case model.StorageDefault:
		default:
			return Plan{}, fmt.Errorf("unsupported volume placement %q", volume.Placement)
		}
		plan.Volumes = append(plan.Volumes, ResolvedVolume{Module: volume.Module, Name: volume.Name, Guest: volume.Guest, Storage: selected, Placement: volume.Placement, Backup: volume.Backup})
	}
	sort.Slice(plan.Volumes, func(i, j int) bool {
		if plan.Volumes[i].Module != plan.Volumes[j].Module {
			return plan.Volumes[i].Module < plan.Volumes[j].Module
		}
		return plan.Volumes[i].Name < plan.Volumes[j].Name
	})
	return plan, nil
}

// InitializeRunner is the small part of the bootstrap SSH contract needed by
// storage. Keeping it local avoids making storage depend on the Proxmox API
// client and makes the destructive command easy to fixture-test.
type InitializeRunner interface {
	Run(context.Context, string, string, string) ([]byte, error)
}

// Initialize runs the one fixed dedicated-disk initializer over the existing
// fresh-host SSH path. The remote command is intentionally conservative:
// it adopts only the exact expected layout, refuses a system/active disk, and
// requires explicit destructive confirmation before it creates a new layout.
// Reinitialization of a dormant old layout is a separate, opt-in action.
func Initialize(ctx context.Context, runner InitializeRunner, address, user, device string, confirmed, reinitialize bool) error {
	if runner == nil {
		return errors.New("storage initialization runner is required")
	}
	if err := validateDevice(device); err != nil {
		return err
	}
	command, err := InitializationCommand(device, confirmed, reinitialize)
	if err != nil {
		return err
	}
	if user != "root" {
		command = "sudo -n sh -c " + shellQuote(command)
	}
	if _, err := runner.Run(ctx, address, user, command); err != nil {
		return fmt.Errorf("initialize dedicated boetticher storage: %w", err)
	}
	return nil
}

// InitializationCommand returns a reviewable shell command for the fixed 0.4
// layout. It contains no credentials and accepts only a stable by-id device.
// An existing unmounted, non-LVM layout remains a refusal unless both the
// ordinary destructive confirmation and explicit reinitialization flag are
// supplied.
func InitializationCommand(device string, confirmed, reinitialize bool) (string, error) {
	if err := validateDevice(device); err != nil {
		return "", err
	}
	if reinitialize && !confirmed {
		return "", errors.New("storage reinitialization requires destructive confirmation")
	}
	confirmation := "no"
	if confirmed {
		confirmation = "yes"
	}
	quoted := shellQuote(device)
	lines := []string{
		"set -eu",
		"device=" + quoted,
		"test -e \"$device\" && test -b \"$(readlink -f \"$device\")\"",
		"resolved=\"$(readlink -f \"$device\")\"",
		"root_source=\"$(findmnt -no SOURCE /)\"",
		"root_device=\"$root_source\"",
		"while parent=\"$(lsblk -ndo PKNAME \"$root_device\")\"; do [ -z \"$parent\" ] && break; root_device=\"/dev/$parent\"; done",
		"[ \"$resolved\" != \"$root_device\" ] || { echo 'refusing the Proxmox system disk' >&2; exit 42; }",
		"is_target_device_or_partition() { candidate=\"$(readlink -f \"$1\")\"; case \"$candidate\" in \"$resolved\"|\"$resolved\"[0-9]*|\"$resolved\"p[0-9]*) return 0;; esac; return 1; }",
		"if vgs --noheadings --select vg_name=" + VolumeGroup + " 2>/dev/null | grep -q .; then",
		"  pv=\"$(pvs --noheadings --select vg_name=" + VolumeGroup + " -o pv_name | xargs)\"",
		"  [ \"$(readlink -f \"$pv\")\" = \"$resolved\" ] || { echo 'existing boetticher VG is on an unexpected device' >&2; exit 43; }",
		"  [ \"$(lvs --noheadings -o lv_attr " + VolumeGroup + "/" + ThinPool + " | xargs | cut -c1)\" = t ] || { echo 'boetticher thin pool is missing or not thin' >&2; exit 44; }",
		"  lvs --noheadings " + VolumeGroup + "/" + BackupLogicalVol + " >/dev/null || { echo 'boetticher backup LV is missing' >&2; exit 45; }",
		"  [ \"$(blkid -s TYPE -o value /dev/" + VolumeGroup + "/" + BackupLogicalVol + ")\" = " + BackupFilesystem + " ] || { echo 'boetticher backup filesystem is not ext4' >&2; exit 46; }",
		"else",
		"  [ " + shellQuote(confirmation) + " = yes ] || { echo 'dedicated storage initialization is destructive; repeat with explicit confirmation' >&2; exit 50; }",
		"  if lsblk -nrpo MOUNTPOINT \"$resolved\" | awk 'NF { found=1 } END { exit found ? 0 : 1 }'; then echo 'refusing a mounted data disk' >&2; exit 51; fi",
		"  if swapon --noheadings --raw --output NAME 2>/dev/null | ( while IFS= read -r swap; do is_target_device_or_partition \"$swap\" && exit 0; done; exit 1 ); then echo 'refusing a disk with active swap' >&2; exit 52; fi",
		"  if pvs --noheadings -o pv_name 2>/dev/null | ( while IFS= read -r pv; do pv=\"$(printf %s \"$pv\" | xargs)\"; [ -n \"$pv\" ] && is_target_device_or_partition \"$pv\" && exit 0; done; exit 1 ); then echo 'refusing a disk already used by LVM' >&2; exit 53; fi",
	}
	if reinitialize {
		lines = append(lines,
			"  if wipefs -n \"$resolved\" | grep -q .; then",
			"    wipefs --all --force \"$resolved\"",
			"    command -v partprobe >/dev/null 2>&1 && partprobe \"$resolved\" || true",
			"    command -v udevadm >/dev/null 2>&1 && udevadm settle || true",
			"    if wipefs -n \"$resolved\" | grep -q .; then echo 'refusing to continue while storage signatures remain' >&2; exit 54; fi",
			"  fi",
		)
	} else {
		lines = append(lines, "  if wipefs -n \"$resolved\" | grep -q .; then echo 'refusing a disk with existing filesystem signatures; repeat with --reinitialize after reviewing the exact stable device' >&2; exit 54; fi")
	}
	lines = append(lines, []string{
		"  pvcreate --yes \"$resolved\"",
		"  vgcreate " + VolumeGroup + " \"$resolved\"",
		"  lvcreate -l " + ThinPoolPercent + " -T " + VolumeGroup + "/" + ThinPool,
		"  lvcreate -l " + BackupLVPercent + " -n " + BackupLogicalVol + " " + VolumeGroup,
		"  mkfs." + BackupFilesystem + " -F /dev/" + VolumeGroup + "/" + BackupLogicalVol,
		"fi",
		"install -d -m 0750 -o root -g root " + BackupMount,
		"uuid=\"$(blkid -s UUID -o value /dev/" + VolumeGroup + "/" + BackupLogicalVol + ")\"",
		"test -n \"$uuid\"",
		"grep -Fq \"UUID=$uuid " + BackupMount + " " + BackupFilesystem + " defaults,nofail 0 2\" /etc/fstab || printf '%s\\n' \"UUID=$uuid " + BackupMount + " " + BackupFilesystem + " defaults,nofail 0 2\" >> /etc/fstab",
		"mountpoint -q " + BackupMount + " || mount " + BackupMount,
		"if pvesm status --storage " + GuestStorageID + " >/dev/null 2>&1; then pvesm config " + GuestStorageID + " | grep -Fq 'vgname " + VolumeGroup + "' && pvesm config " + GuestStorageID + " | grep -Fq 'thinpool " + ThinPool + "' || { echo 'boetticher guest storage has a conflicting definition' >&2; exit 56; }; else pvesm add lvmthin " + GuestStorageID + " --vgname " + VolumeGroup + " --thinpool " + ThinPool + " --content images,rootdir; fi",
		"if pvesm status --storage " + BackupStorageID + " >/dev/null 2>&1; then pvesm config " + BackupStorageID + " | grep -Fq 'path " + BackupMount + "' || { echo 'boetticher backup storage has a conflicting definition' >&2; exit 57; }; else pvesm add dir " + BackupStorageID + " --path " + BackupMount + " --content backup; fi",
		"pvesm status --storage " + GuestStorageID + " >/dev/null",
		"pvesm status --storage " + BackupStorageID + " >/dev/null",
	}...)
	return strings.Join(lines, "\n"), nil
}

func validateDevice(device string) error {
	return model.ValidateStableDevice(device)
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
