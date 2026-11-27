---
name: boetticher-patching
description: Plan and review operator-authorized OS package maintenance for the Boetticher Controller, Proxmox Host, and supported Debian or Ubuntu guests. Excludes OpenWrt provider upgrades and guest application updates.
---

# Boetticher OS maintenance

Use scripts/maintain-homelab.py as a read-only preflight. It must run on the installed Controller as root so it can use the Controller's pinned Host key. Stream the checked-in script to the installed Controller with strict SSH host-key checking; supply exactly one target and its expected hostname or enrolled node name. The script has no apply mode and does not refresh package indexes.

Before any package mutation, get explicit authorization for the target and maintenance window. Define a recoverable backup scope. A user-authorized exclusion for replaceable bulk data is acceptable; the backup must still cover the boot/system disk and all state needed to reinstall and operate the software, including package/runtime state, service and Compose definitions, persistent application configuration, databases, and required credential recovery references. Record excluded disks or mounts, verify software can boot and recover with excluded data absent, and test the software restore before accepting the backup. Use application-consistent database exports or quiesce active databases during capture. The helper lists archives but cannot prove their contents or restoreability, so keep recovery at HOLD until these checks pass.

For QEMU disk exclusions, inspect and verify the per-drive backup selection in both the VM configuration and resulting archive. Restore temporary backup-scope flags to their exact prior values after capture. Persist an exclusion only with explicit operator intent and after confirming the owning reconciliation path will preserve it. Preserve all unrelated guest and Host state.

For package plans, refresh package indexes only inside an authorized maintenance run, then review a fresh full-upgrade simulation. Refuse package removals, distribution/source changes, identity mismatches, and any failed or incomplete readiness check. Apply one target at a time. Use the installed Controller bootstrap procedure for Controller packages and strict Controller-to-Host SSH for Proxmox. Restrict the generic guest path to Debian and Ubuntu.

Keep OpenWrt on its supported provider/module workflow. Do not fold guest applications, images, firmware, or major distribution upgrades into routine OS maintenance. Preserve VM startup policy, including an existing onboot=0, until its purpose is understood.

Do not reboot automatically. After package work, compare running and installed kernels, report the pending reboot and recovery state, and use the installed reboot flow only after separate authorization. Do not create a recurring schedule until the operator chooses a cadence and a recovery-ready run has completed successfully.

Treat the accepted 30-minute outage as a ceiling, not a recovery guarantee. Finish preparation before the window and reserve time for service and access recovery; do not start another target when the remaining window is insufficient. Never kill an active apt or dpkg transaction to meet the window. A hardware or boot failure may outlast it.
