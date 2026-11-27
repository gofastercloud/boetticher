# Homelab maintenance preflight

maintain-homelab.py gathers a read-only package and recovery preflight for one
installed Boetticher Controller, Proxmox Host, or Debian/Ubuntu guest. It uses
the installed Controller CLI for target identity and the Controller's pinned
Host SSH key for Host-native inventory.

Run it from the Mac by streaming the checked-in script to the Controller. Use
the Controller's verified SSH name or address and pass the expected identity:

~~~sh
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes pi@CONTROLLER \
  "sudo -n python3 - --target host --expect-name PROXMOX_NODE" \
  < scripts/maintain-homelab.py
~~~

Select exactly one target:

~~~text
controller
host
lxc:VMID
qemu:VMID
~~~

For example, a guest preflight supplies both identities:

~~~sh
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes pi@CONTROLLER \
  "sudo -n python3 - --target lxc:VMID --expect-name GUEST --expect-node PROXMOX_NODE" \
  < scripts/maintain-homelab.py
~~~

For a Controller target, --expect-name is its current hostname. For the Host,
it is the enrolled Proxmox node name. For a guest, pass --expect-name with the
expected guest name and --expect-node with the enrolled Proxmox node name. A
mismatch stops the preflight before it queries that guest.

The helper reads the current package indexes and runs simulated full upgrades.
It never runs apt-get update, installs or removes packages, changes
configuration, or reboots. It reports proposed removals as HOLD. OpenWrt is
identified but excluded from APT simulation; use its provider/module procedure.
Only one target can be inspected per invocation.

The helper lists registered backup archives for the selected guest or Host
storage. Archive presence does not prove archive contents, freshness, or
restorability. A software-only backup may exclude replaceable bulk data when
that exclusion is explicit and authorized. Verify that the archive covers the
boot/system disk and all state needed to reinstall and operate the software:
package/runtime state, service and Compose definitions, persistent application
configuration, databases, and required credential recovery references. Record
excluded disks or mounts and confirm software can boot and recover with the
excluded data unavailable. Test the restore scope before accepting the backup.
For QEMU guests, verify per-drive inclusion in the archived configuration; do
not assume path exclusions apply to VM disks. Take a database-consistent backup
or quiesce active databases during capture.

Reboot need is judged by comparing the running kernel with the newest
installed one (KERNEL_PENDING), because Proxmox does not write the Debian
reboot marker. Guest backups report BACKUP_FRESHNESS against the Host clock;
--max-backup-age-hours (default 168) sets the limit. Exit status is 0 when only
the standing recovery review remains, 3 when a package-plan or backup HOLD
blocks an upgrade, and 2 when identity or a read-only check failed. --json
emits one result with status, blocking lines, and the full report.

The output retains a recovery HOLD and has no apply mode. Before any separately
authorized package run, verify archive scope, free capacity, restore path,
target identity, and recovery access.

Unattended security patching is installed on the Controller (bootstrap), the
Host (host apply), and Debian guests (base image, observability base, and the
media VM image). It applies Debian security-origin updates only, never removes
packages, and never reboots; pending kernels are reported by this preflight.
Guest images carry a live security.debian.org source beside the frozen
snapshot so that fixes published after the image build are visible. Existing
guests receive this only when their image is rebuilt and redeployed. Proxmox's
own packages and OpenWrt stay on the gated procedures below.

Controller package maintenance uses the installed
boetticher controller bootstrap procedure. Proxmox package work uses the
strict Controller-to-Host SSH identity and a reviewed apt-get -s
dist-upgrade plan. Guest package work is limited to Debian and Ubuntu.
Reboots remain a separate operator decision through the installed reboot flow.
This helper does not schedule future work.

Treat a 30-minute outage allowance as a ceiling, not a recovery guarantee. Finish preparation before the window and reserve time for service and access recovery; do not start another target when the remaining window is insufficient. Never terminate an active apt or dpkg transaction to meet the window. A hardware or boot failure may take longer to recover.

The helper does not update OpenWrt, firmware, images, or guest applications. It
also does not change guest startup policy. In particular, preserve an existing
onboot=0 until its reason is known.

See the reusable Boetticher patching skill at
../.codex/skills/boetticher-patching/SKILL.md for the maintenance gates after
this preflight.
