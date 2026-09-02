package storage

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
)

type recordingInitializeRunner struct {
	command string
}

func (r *recordingInitializeRunner) Run(_ context.Context, _, _, command string) ([]byte, error) {
	r.command = command
	return nil, nil
}

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

func TestArrDownloadsUseDedicatedDataStorageAndRequireIt(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	enabled := true
	config.Modules.AirVPN = &model.AirVPNModuleConfig{Enabled: &enabled, Servers: "australia"}
	config.Modules.Arr = &model.ArrModuleConfig{Enabled: &enabled, Network: model.ModuleNetworkAirVPN}
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PlanFromSite(site); err == nil || !strings.Contains(err.Error(), "arr volume downloads requires dedicated") {
		t.Fatalf("single-disk ARR download storage was accepted: %v", err)
	}
	site.StorageProfile = "dedicated-data-disk"
	site.StorageDevice = "/dev/disk/by-id/ata-example-data"
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	for _, volume := range plan.Volumes {
		if volume.Module == "arr" && volume.Name == "downloads" {
			if volume.Storage != GuestStorageID || volume.Placement != model.StorageRequireDataDisk || volume.Backup {
				t.Fatalf("ARR download volume storage = %#v", volume)
			}
			return
		}
	}
	t.Fatal("ARR download volume is missing from dedicated storage plan")
}

func TestInitializationCommandIsStableAndGuarded(t *testing.T) {
	command, err := InitializationCommand("/dev/disk/by-id/ata-example-data", true, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"findmnt -no SOURCE /",
		"refusing the Proxmox system disk",
		"wipefs -n",
		"repeat with --reinitialize after reviewing the exact stable device",
		"pvcreate --yes",
		"vgcreate vg_boetticher",
		"lvcreate -l 70%VG -T vg_boetticher/thinpool",
		"lvcreate -l 20%VG -n backup vg_boetticher",
		"mkfs.ext4 -F /dev/vg_boetticher/backup",
		"UUID=$uuid /srv/boetticher/backups ext4 defaults,nofail 0 2",
		"pvesm add lvmthin boetticher-thin",
		"pvesm add dir boetticher-backups",
		"pvesh get /storage/boetticher-thin --output-format json",
		"pvesh get /storage/boetticher-backups --output-format json",
		"perl -MJSON::PP=decode_json",
	} {
		if !strings.Contains(command, want) {
			t.Fatalf("initialization command does not contain %q:\n%s", want, command)
		}
	}
	if strings.Contains(command, "wipefs --all --force") {
		t.Fatal("ordinary storage initialization can discard an existing layout")
	}
	if strings.Contains(command, "pvesm config") {
		t.Fatal("storage initialization uses the removed pvesm config subcommand")
	}
	if strings.Contains(command, "/dev/sd") || strings.Contains(command, "/dev/nvme") {
		t.Fatal("initialization command embedded a transient device identity")
	}
	withoutConfirmation, err := InitializationCommand("/dev/disk/by-id/ata-example-data", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(withoutConfirmation, "dedicated storage initialization is destructive") {
		t.Fatal("unconfirmed initialization did not retain its destructive guard")
	}
}

func TestInitializationCommandRequiresExplicitReinitializeForOldLayouts(t *testing.T) {
	if _, err := InitializationCommand("/dev/disk/by-id/ata-example-data", false, true); err == nil {
		t.Fatal("reinitialization without destructive confirmation was accepted")
	}
	command, err := InitializationCommand("/dev/disk/by-id/ata-example-data", true, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"refusing a mounted data disk",
		"refusing a disk with active swap",
		"refusing a disk already used by LVM",
		"wipefs --all --force \"$resolved\"",
		"refusing to continue while storage signatures remain",
	} {
		if !strings.Contains(command, want) {
			t.Fatalf("reinitialization command does not contain %q:\n%s", want, command)
		}
	}
}

func TestInitializationCommandHasValidShellSyntax(t *testing.T) {
	for _, reinitialize := range []bool{false, true} {
		command, err := InitializationCommand("/dev/disk/by-id/ata-example-data", true, reinitialize)
		if err != nil {
			t.Fatal(err)
		}
		check := exec.Command("sh", "-n")
		check.Stdin = strings.NewReader(command)
		if output, err := check.CombinedOutput(); err != nil {
			t.Fatalf("storage command syntax (reinitialize=%t): %v\n%s\n%s", reinitialize, err, output, command)
		}
	}
}

func TestInitializationRejectsTransientOrUnsafeDevice(t *testing.T) {
	for _, device := range []string{"/dev/sdb", "/dev/disk/by-id/foo bar", "/dev/disk/by-id/foo\nbar", "/dev/disk/by-id/../sdb", "/dev/disk/by-id/foo/../../sdb", "/dev/disk/by-id/foo/", "/dev/disk/by-id/foo\\bar", ""} {
		if _, err := InitializationCommand(device, true, false); err == nil {
			t.Fatalf("unsafe storage device %q was accepted", device)
		}
	}
}

func TestInitializationAcceptsDirectStableDeviceNames(t *testing.T) {
	for _, device := range []string{"/dev/disk/by-id/ata-Samsung_SSD_870", "/dev/disk/by-id/usb-Generic_Flash", "/dev/disk/by-id/nvme-eui.1234"} {
		if _, err := InitializationCommand(device, true, false); err != nil {
			t.Fatalf("valid stable device %q was rejected: %v", device, err)
		}
	}
}

func TestInitializationUsesNonInteractiveSudoForNonRoot(t *testing.T) {
	runner := &recordingInitializeRunner{}
	if err := Initialize(context.Background(), runner, "192.0.2.10", "labadmin", "/dev/disk/by-id/ata-example-data", true, false); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(runner.command, "sudo -n sh -c ") {
		t.Fatalf("dedicated storage initialization did not use non-interactive sudo: %q", runner.command)
	}
	rootRunner := &recordingInitializeRunner{}
	if err := Initialize(context.Background(), rootRunner, "192.0.2.10", "root", "/dev/disk/by-id/ata-example-data", true, false); err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(rootRunner.command, "sudo -n ") {
		t.Fatalf("root storage initialization unnecessarily used sudo: %q", rootRunner.command)
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

func TestLocalStorageContentIsProfileSpecificAndDeterministic(t *testing.T) {
	single, err := LocalStorageContent("single-disk")
	if err != nil || strings.Join(single, ",") != "backup,images,rootdir,snippets,vztmpl" {
		t.Fatalf("single-disk local content = %v, %v", single, err)
	}
	dedicated, err := LocalStorageContent("dedicated-data-disk")
	if err != nil || strings.Join(dedicated, ",") != "images,rootdir,snippets,vztmpl" {
		t.Fatalf("dedicated-data-disk local content = %v, %v", dedicated, err)
	}
	if _, err := LocalStorageContent("unknown"); err == nil {
		t.Fatal("unknown storage profile was accepted")
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

func TestStatusCommandReportsAbsentDedicatedStorageWithoutMalformedFields(t *testing.T) {
	command, err := StatusCommand("/dev/disk/by-id/ata-example-data")
	if err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	for name, script := range map[string]string{
		"readlink": "#!/bin/sh\nexit 1\n",
		"vgs":      "#!/bin/sh\nexit 0\n",
		"lvs":      "#!/bin/sh\nexit 0\n",
		"blkid":    "#!/bin/sh\nexit 1\n",
		"findmnt":  "#!/bin/sh\nexit 1\n",
		"pvesm":    "#!/bin/sh\nexit 1\n",
		"df":       "#!/bin/sh\nexit 1\n",
	} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	run := exec.Command("sh", "-c", command)
	run.Env = append(os.Environ(), "PATH="+binDir+":"+os.Getenv("PATH"))
	output, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("status command failed: %v\n%s\n%s", err, output, command)
	}
	status, err := ParseStatus(string(output))
	if err != nil {
		t.Fatalf("status parser rejected absent dedicated storage: %v\n%s", err, output)
	}
	if status.VolumeGroup != "missing" || status.ThinPool != "missing" || status.BackupLV != "missing" || status.Capacity != "unavailable" {
		t.Fatalf("unexpected absent storage status: %#v", status)
	}
}
