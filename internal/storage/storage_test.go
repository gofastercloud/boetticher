package storage

import (
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestDedicatedPlanUsesFixedLayout(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	site.StorageProfile = "dedicated-data-disk"
	site.StorageDevice = "/dev/disk/by-id/ata-example-data"
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Device != site.StorageDevice || plan.VolumeGroup != VolumeGroup || plan.ThinPool != ThinPool || plan.BackupLV != BackupLogicalVol {
		t.Fatalf("unexpected dedicated layout: %#v", plan)
	}
	if plan.GuestStorage != GuestStorageID || plan.BackupStorage != BackupStorageID || plan.BackupMount != BackupMount {
		t.Fatalf("unexpected Proxmox storage projection: %#v", plan)
	}
}

func TestInitializationCommandIsStableAndGuarded(t *testing.T) {
	command, err := InitializationCommand("/dev/disk/by-id/ata-example-data", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"findmnt -no SOURCE /",
		"refusing the Proxmox system disk",
		"wipefs -n",
		"pvcreate --yes",
		"vgcreate vg_boetticher",
		"lvcreate -l 70%VG -T vg_boetticher/thinpool",
		"lvcreate -l 20%VG -n backup vg_boetticher",
		"mkfs.ext4 -F /dev/vg_boetticher/backup",
		"UUID=$uuid /srv/boetticher/backups ext4 defaults,nofail 0 2",
		"pvesm add lvmthin boetticher-thin",
		"pvesm add dir boetticher-backups",
	} {
		if !strings.Contains(command, want) {
			t.Fatalf("initialization command does not contain %q:\n%s", want, command)
		}
	}
	if strings.Contains(command, "/dev/sd") || strings.Contains(command, "/dev/nvme") {
		t.Fatal("initialization command embedded a transient device identity")
	}
	withoutConfirmation, err := InitializationCommand("/dev/disk/by-id/ata-example-data", false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(withoutConfirmation, "dedicated storage initialization is destructive") {
		t.Fatal("unconfirmed initialization did not retain its destructive guard")
	}
}

func TestInitializationRejectsTransientOrUnsafeDevice(t *testing.T) {
	for _, device := range []string{"/dev/sdb", "/dev/disk/by-id/foo bar", "/dev/disk/by-id/foo\nbar", ""} {
		if _, err := InitializationCommand(device, true); err == nil {
			t.Fatalf("unsafe storage device %q was accepted", device)
		}
	}
}

func TestSingleDiskPlanDoesNotRequireDevice(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Profile != "single-disk" || plan.Device != "" || plan.GuestStorage != "local" || plan.BackupStorage != "local" {
		t.Fatalf("unexpected single-disk plan: %#v", plan)
	}
}

func TestStatusCommandAndParserUseFixedReadOnlyFields(t *testing.T) {
	command, err := StatusCommand("/dev/disk/by-id/ata-example-data")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"vgs --noheadings", "lvs --noheadings", "blkid -s TYPE", "findmnt -no TARGET", "pvesm status --storage boetticher-thin", "pvesm status --storage boetticher-backups", "df -hP /srv/boetticher/backups"} {
		if !strings.Contains(command, want) {
			t.Fatalf("status command does not contain %q:\n%s", want, command)
		}
	}
	if strings.Contains(command, "pvcreate") || strings.Contains(command, "mkfs") || strings.Contains(command, "rm ") {
		t.Fatal("storage status command contains a destructive operation")
	}
	status, err := ParseStatus("device=/dev/disk/by-id/ata-example-data\ndevice_path=/dev/sdb\nvolume_group=vg_boetticher\nthin_pool=thinpool\nbackup_lv=backup\nfilesystem=ext4\nmount=/srv/boetticher/backups\nguest_storage=active\nbackup_storage=active\ncapacity=/dev/mapper/vg_boetticher-backup 100G 1G 99G 1% /srv/boetticher/backups\n")
	if err != nil {
		t.Fatal(err)
	}
	if status.VolumeGroup != VolumeGroup || status.Filesystem != BackupFilesystem || status.Mount != BackupMount {
		t.Fatalf("unexpected parsed storage status: %#v", status)
	}
}
