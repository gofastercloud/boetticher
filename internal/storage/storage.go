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
	VolumeGroup                     = "vg_boetticher"
	ThinPool                        = "thinpool"
	BackupLogicalVol                = "backup"
	BackupMount                     = "/srv/boetticher/backups"
	BackupFilesystem                = "ext4"
	GuestStorageID                  = "boetticher-thin"
	BackupStorageID                 = "boetticher-backups"
	ThinPoolPercent                 = "70%VG"
	BackupLVPercent                 = "20%VG"
	USBTransportCompatibilityConfig = "/etc/default/grub.d/99-boetticher-usb-storage-compat.cfg"
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

// Plan is the complete, fixed 0.5 storage contract. It describes only
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
// requires explicit destructive confirmation before it creates or resets a
// layout. Reinitialization of the exact Boetticher layout is a separate,
// opt-in action and refuses to run while any Proxmox guests are configured.
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

// InitializationCommand returns a reviewable shell command for the fixed 0.5
// layout. It contains no credentials and accepts only a stable by-id device.
// An existing layout remains untouched unless both the ordinary destructive
// confirmation and explicit reinitialization flag are supplied. A reinitialize
// operation only resets an exact existing Boetticher VG on the configured
// device, after refusing configured guests and conflicting storage IDs.
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
		"layout_create=0",
		"if vgs --noheadings --select vg_name=" + VolumeGroup + " 2>/dev/null | grep -q .; then",
		"  pv=\"$(pvs --noheadings --select vg_name=" + VolumeGroup + " -o pv_name | xargs)\"",
		"  [ \"$(readlink -f \"$pv\")\" = \"$resolved\" ] || { echo 'existing boetticher VG is on an unexpected device' >&2; exit 43; }",
	}
	if reinitialize {
		lines = append(lines,
			"  [ \"$(lvs --noheadings -o lv_attr "+VolumeGroup+"/"+ThinPool+" | xargs | cut -c1)\" = t ] || { echo 'boetticher thin pool is missing or not thin' >&2; exit 44; }",
			"  if lvs --noheadings "+VolumeGroup+"/"+BackupLogicalVol+" >/dev/null 2>&1; then [ \"$(blkid -s TYPE -o value /dev/"+VolumeGroup+"/"+BackupLogicalVol+")\" = "+BackupFilesystem+" ] || { echo 'boetticher backup filesystem is not ext4' >&2; exit 46; }; fi",
		)
	} else {
		lines = append(lines,
			"  [ \"$(lvs --noheadings -o lv_attr "+VolumeGroup+"/"+ThinPool+" | xargs | cut -c1)\" = t ] || { echo 'boetticher thin pool is missing or not thin' >&2; exit 44; }",
			"  lvs --noheadings "+VolumeGroup+"/"+BackupLogicalVol+" >/dev/null || { echo 'boetticher backup LV is missing' >&2; exit 45; }",
			"  [ \"$(blkid -s TYPE -o value /dev/"+VolumeGroup+"/"+BackupLogicalVol+")\" = "+BackupFilesystem+" ] || { echo 'boetticher backup filesystem is not ext4' >&2; exit 46; }",
		)
	}
	if reinitialize {
		lines = append(lines,
			"  if [ "+shellQuote(confirmation)+" = yes ]; then",
			"    if qm list 2>/dev/null | awk 'NR > 1 && NF { found=1 } END { exit found ? 0 : 1 }'; then echo 'refusing to reset storage while Proxmox QEMU guests are configured' >&2; exit 58; fi",
			"    if pct list 2>/dev/null | awk 'NR > 1 && NF { found=1 } END { exit found ? 0 : 1 }'; then echo 'refusing to reset storage while Proxmox containers are configured' >&2; exit 59; fi",
			"    if mountpoint -q "+BackupMount+"; then",
			"      mounted_source=\"$(findmnt -no SOURCE "+BackupMount+")\"",
			"      [ \"$(readlink -f \"$mounted_source\")\" = \"$(readlink -f /dev/"+VolumeGroup+"/"+BackupLogicalVol+")\" ] || { echo 'refusing to reset an unexpected filesystem mounted at the Boetticher backup path' >&2; exit 60; }",
			"      umount "+BackupMount,
			"    fi",
			"    if pvesm status --storage "+GuestStorageID+" >/dev/null 2>&1; then "+storageConfigurationCheck(GuestStorageID, "type=lvmthin", "vgname="+VolumeGroup, "thinpool="+ThinPool, "content=images", "content=rootdir")+" || { echo 'boetticher guest storage has a conflicting definition' >&2; exit 61; }; fi",
			"    if pvesm status --storage "+BackupStorageID+" >/dev/null 2>&1; then "+storageConfigurationCheck(BackupStorageID, "type=dir", "path="+BackupMount, "content=backup")+" || { echo 'boetticher backup storage has a conflicting definition' >&2; exit 62; }; fi",
			"    if pvesm status --storage "+GuestStorageID+" >/dev/null 2>&1; then pvesm remove "+GuestStorageID+"; fi",
			"    if pvesm status --storage "+BackupStorageID+" >/dev/null 2>&1; then pvesm remove "+BackupStorageID+"; fi",
			"    sed -i "+shellQuote("\\|[[:space:]]"+BackupMount+"[[:space:]]|d")+" /etc/fstab",
			"    vgchange --activate n "+VolumeGroup,
			"    vgremove --yes --force "+VolumeGroup,
			"    pvremove --yes --force \"$resolved\"",
			"    wipefs --all --force \"$resolved\"",
			"    command -v partprobe >/dev/null 2>&1 && partprobe \"$resolved\" || true",
			"    command -v udevadm >/dev/null 2>&1 && udevadm settle || true",
			"    if wipefs -n \"$resolved\" | grep -q .; then echo 'refusing to continue while storage signatures remain after reset' >&2; exit 63; fi",
			"    layout_create=1",
			"  fi",
		)
	}
	lines = append(lines,
		"else",
		"  [ "+shellQuote(confirmation)+" = yes ] || { echo 'dedicated storage initialization is destructive; repeat with explicit confirmation' >&2; exit 50; }",
		"  if lsblk -nrpo MOUNTPOINT \"$resolved\" | awk 'NF { found=1 } END { exit found ? 0 : 1 }'; then echo 'refusing a mounted data disk' >&2; exit 51; fi",
		"  if swapon --noheadings --raw --output NAME 2>/dev/null | ( while IFS= read -r swap; do is_target_device_or_partition \"$swap\" && exit 0; done; exit 1 ); then echo 'refusing a disk with active swap' >&2; exit 52; fi",
		"  if pvs --noheadings -o pv_name 2>/dev/null | ( while IFS= read -r pv; do pv=\"$(printf %s \"$pv\" | xargs)\"; [ -n \"$pv\" ] && is_target_device_or_partition \"$pv\" && exit 0; done; exit 1 ); then echo 'refusing a disk already used by LVM' >&2; exit 53; fi",
		"  layout_create=1",
	)
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
		"fi",
		"if [ \"$layout_create\" -eq 1 ]; then",
		"  pvcreate --yes \"$resolved\"",
		"  vgcreate " + VolumeGroup + " \"$resolved\"",
		"  lvcreate --yes -l " + ThinPoolPercent + " -T " + VolumeGroup + "/" + ThinPool,
		"  lvcreate --yes -l " + BackupLVPercent + " -n " + BackupLogicalVol + " " + VolumeGroup,
		"  mkfs." + BackupFilesystem + " -F /dev/" + VolumeGroup + "/" + BackupLogicalVol,
		"fi",
		"install -d -m 0750 -o root -g root " + BackupMount,
		"uuid=\"$(blkid -s UUID -o value /dev/" + VolumeGroup + "/" + BackupLogicalVol + ")\"",
		"test -n \"$uuid\"",
		"grep -Fq \"UUID=$uuid " + BackupMount + " " + BackupFilesystem + " defaults,nofail 0 2\" /etc/fstab || printf '%s\\n' \"UUID=$uuid " + BackupMount + " " + BackupFilesystem + " defaults,nofail 0 2\" >> /etc/fstab",
		"mountpoint -q " + BackupMount + " || mount " + BackupMount,
		"if pvesm status --storage " + GuestStorageID + " >/dev/null 2>&1; then " + storageConfigurationCheck(GuestStorageID, "type=lvmthin", "vgname="+VolumeGroup, "thinpool="+ThinPool, "content=images", "content=rootdir") + " || { echo 'boetticher guest storage has a conflicting definition' >&2; exit 56; }; else pvesm add lvmthin " + GuestStorageID + " --vgname " + VolumeGroup + " --thinpool " + ThinPool + " --content images,rootdir; fi",
		"if pvesm status --storage " + BackupStorageID + " >/dev/null 2>&1; then " + storageConfigurationCheck(BackupStorageID, "type=dir", "path="+BackupMount, "content=backup") + " || { echo 'boetticher backup storage has a conflicting definition' >&2; exit 57; }; else pvesm add dir " + BackupStorageID + " --path " + BackupMount + " --content backup; fi",
		"pvesm status --storage " + GuestStorageID + " >/dev/null",
		"pvesm status --storage " + BackupStorageID + " >/dev/null",
	}...)
	return strings.Join(lines, "\n"), nil
}

// ConfigureUSBTransportCompatibility writes a narrowly scoped, persistent
// fallback for a USB bridge which drops the configured data disk while using
// UAS. It discovers the bridge from the stable configured device rather than
// accepting a volatile block path or a caller-supplied USB ID. The fallback is
// reversible by removing only the Boetticher-owned GRUB drop-in and regenerating
// GRUB; rebooting is separately explicit.
func ConfigureUSBTransportCompatibility(ctx context.Context, runner InitializeRunner, address, user, device string, reboot, allowSharedBridge bool) error {
	if runner == nil {
		return errors.New("storage USB transport compatibility runner is required")
	}
	command, err := USBTransportCompatibilityCommand(device, reboot, allowSharedBridge)
	if err != nil {
		return err
	}
	if user != "root" {
		command = "sudo -n sh -c " + shellQuote(command)
	}
	if _, err := runner.Run(ctx, address, user, command); err != nil {
		return fmt.Errorf("configure dedicated storage USB transport compatibility: %w", err)
	}
	return nil
}

// USBTransportCompatibilityCommand returns the advanced, fixed recovery
// command for a UAS transport failure. It owns exactly one GRUB drop-in,
// validates the generated GRUB configuration, and refuses a shared bridge
// identifier unless the caller deliberately acknowledges that scope.
func USBTransportCompatibilityCommand(device string, reboot, allowSharedBridge bool) (string, error) {
	if err := validateDevice(device); err != nil {
		return "", err
	}
	sharedConfirmation := "no"
	if allowSharedBridge {
		sharedConfirmation = "yes"
	}
	quoted := shellQuote(device)
	lines := []string{
		"set -eu",
		"device=" + quoted,
		"test -e \"$device\" && test -b \"$(readlink -f \"$device\")\"",
		"resolved=\"$(readlink -f \"$device\")\"",
		"block=\"$(basename \"$resolved\")\"",
		"sys=\"/sys/class/block/$block/device\"",
		"vendor=\"\"",
		"product=\"\"",
		"while [ \"$sys\" != / ] && [ -n \"$sys\" ]; do",
		"  if [ -r \"$sys/idVendor\" ] && [ -r \"$sys/idProduct\" ]; then",
		"    vendor=\"$(tr '[:upper:]' '[:lower:]' < \"$sys/idVendor\" | tr -d '[:space:]')\"",
		"    product=\"$(tr '[:upper:]' '[:lower:]' < \"$sys/idProduct\" | tr -d '[:space:]')\"",
		"    break",
		"  fi",
		"  next=\"$(readlink -f \"$sys/..\")\"",
		"  [ \"$next\" != \"$sys\" ] || break",
		"  sys=\"$next\"",
		"done",
		"printf '%s\\n' \"$vendor\" | grep -Eq '^[[:xdigit:]]{4}$' || { echo 'configured storage device does not resolve to a USB vendor ID' >&2; exit 60; }",
		"printf '%s\\n' \"$product\" | grep -Eq '^[[:xdigit:]]{4}$' || { echo 'configured storage device does not resolve to a USB product ID' >&2; exit 61; }",
		"allow_shared=" + shellQuote(sharedConfirmation),
		"matches=\"$(lsusb -d \"$vendor:$product\" 2>/dev/null | wc -l | tr -d '[:space:]')\"",
		"case \"$matches\" in ''|*[!0-9]*) echo 'cannot determine matching USB bridge count' >&2; exit 62;; esac",
		"if [ \"$matches\" -gt 1 ] && [ \"$allow_shared\" != yes ]; then echo 'USB transport recovery would affect multiple identical bridges; repeat with --allow-shared-usb-bridge-quirk' >&2; exit 63; fi",
		"config=" + USBTransportCompatibilityConfig,
		"line=\"GRUB_CMDLINE_LINUX_DEFAULT=\\\"\\$GRUB_CMDLINE_LINUX_DEFAULT usb-storage.quirks=$vendor:$product:u\\\"\"",
		"install -d -m 0755 /etc/default/grub.d",
		"if [ -e \"$config\" ] && ! grep -qxF \"$line\" \"$config\"; then echo 'existing Boetticher USB transport configuration is not the expected content' >&2; exit 64; fi",
		"tmp=\"$(mktemp /etc/default/grub.d/.boetticher-storage-compat.XXXXXX)\"",
		"trap 'rm -f \"$tmp\"' EXIT",
		"printf '%s\\n' \"$line\" > \"$tmp\"",
		"chmod 0644 \"$tmp\"",
		"mv -f \"$tmp\" \"$config\"",
		"update-grub",
		"grub-script-check /boot/grub/grub.cfg",
		"grep -Fq \"usb-storage.quirks=$vendor:$product:u\" /boot/grub/grub.cfg || { echo 'generated GRUB configuration is missing the USB storage compatibility quirk' >&2; exit 65; }",
		"printf 'usb_storage_quirk=%s\\n' \"$vendor:$product:u\"",
		"printf 'matching_usb_bridges=%s\\n' \"$matches\"",
	}
	if reboot {
		lines = append(lines,
			"command -v systemd-run >/dev/null 2>&1 || { echo 'systemd-run is required to schedule the controlled reboot' >&2; exit 66; }",
			"systemd-run --unit=boetticher-storage-reboot --on-active=5s --collect /usr/bin/systemctl reboot",
			"printf 'reboot=scheduled\\n'",
		)
	} else {
		lines = append(lines, "printf 'reboot=required\\n'")
	}
	return strings.Join(lines, "\n"), nil
}

func validateDevice(device string) error {
	return model.ValidateStableDevice(device)
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

// storageConfigurationCheck reads the supported Proxmox storage API through
// pvesh. PVE 9 no longer provides the old "pvesm config" subcommand, while
// the API supplies the structured configuration we need to validate before
// accepting an existing storage ID.
func storageConfigurationCheck(storageID string, expected ...string) string {
	const program = `my ($storage, @expected) = @ARGV;
my $config = eval { decode_json(do { local $/; <STDIN> }) };
exit 1 if $@ || ref($config) ne q(HASH);
exit 1 unless ($config->{storage} // q()) eq $storage;
my %content = map { $_ => 1 } split /,/, ($config->{content} // q());
for my $entry (@expected) {
  my ($field, $value) = split /=/, $entry, 2;
  exit 1 unless defined $value;
  if ($field eq q(content)) {
    exit 1 unless $content{$value};
    next;
  }
  exit 1 unless ($config->{$field} // q()) eq $value;
}`
	arguments := make([]string, 0, len(expected)+1)
	arguments = append(arguments, shellQuote(storageID))
	for _, entry := range expected {
		arguments = append(arguments, shellQuote(entry))
	}
	return "pvesh get /storage/" + storageID + " --output-format json | perl -MJSON::PP=decode_json -e " + shellQuote(program) + " " + strings.Join(arguments, " ")
}
