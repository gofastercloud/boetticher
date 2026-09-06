---
layout: default
title: Controller
section: controller
description: Prepare a Raspberry Pi as the local Boetticher controller.
---

# The local controller

Phase one turns a clean Raspberry Pi OS Lite Trixie installation into the
machine that will eventually run Boetticher’s operator commands. It does not
enroll with Proxmox, create a site, manage lab guests, or deploy the lab.

## Supported starting point

Use Raspberry Pi OS Lite based on Debian 13 (Trixie) with the 64-bit ARM64
userspace on a Raspberry Pi 3, 4, or 5-class board. Keep the existing hostname,
network placement, routes, SSH host keys, operator keys, and `pi` passwordless
sudo access unchanged. Test a new public-key SSH session before running the
installer; `--confirm-key-login` records that acknowledgement before password
authentication is disabled.

## Install from a local payload

The maintainer payload contains a prebuilt ARM64 `boetticher` binary, its
private Ansible playbook and roles, the pinned Azlux public key, an installer,
and `SHA256SUMS`. It contains no site, credential, SOPS, Age, appliance, or
workstation-cache data.

On the Pi, with the payload copied to `/home/pi/controller-release`:

```sh
sudo sh /home/pi/controller-release/install.sh \
  --from-dir /home/pi/controller-release \
  --operator pi \
  --confirm-key-login
```

The installer validates the OS and architecture, verifies the archive checksum,
installs a root-owned versioned release, prepares `/opt/boetticher/venv`, and
invokes the local controller bootstrap. A failed checksum or unsafe archive
leaves the previous installed release untouched. Repeating the same payload is
safe and does not edit an existing versioned release.

The eventual public form is intentionally documented without a fake location:

```sh
curl -fsSL "$RELEASE_BASE/install.sh" | \
  sudo sh -s -- --version "$VERSION" --operator pi --confirm-key-login
```

`RELEASE_BASE` must be a real, published HTTPS release location. Until one is
published, use `--from-dir`; the installer does not silently fall back to local
files after a failed download or checksum check.

## Bootstrap and status

```sh
sudo boetticher controller bootstrap --operator pi --confirm-key-login
sudo boetticher controller status
```

`controller bootstrap` runs one local Ansible playbook and then local readiness
checks. `controller status` is read-only: it does not repair the host, run
Ansible, change Blinkt, load a site, use Age/SOPS, or contact Proxmox.

The controller installs Go 1.26.5 under
`/opt/boetticher/toolchains/go1.26.5/` and Ansible Core 2.19.11 in
`/opt/boetticher/venv/`. The Boetticher binary is always the prebuilt payload;
the Pi does not compile it. Go checks use `GOTOOLCHAIN=local`.

If log2ram was installed during this boot, bootstrap reports a failed readiness
check and asks for an explicit reboot:

```text
Controller readiness: FAIL — reboot required to activate log2ram

Next:
  sudo reboot
```

After reconnecting with a fresh key-authenticated SSH session, rerun bootstrap
and status. A successful final state reports `Controller readiness: PASS`.

## Blinkt

The short-lived `/opt/boetticher/current/controller/libexec/boetticher-bootstrap-led`
helper drives the Pimoroni Blinkt at low brightness through the discovered GPIO
chip and header lines GPIO23/GPIO24. It writes one frame and exits; there is no
controller daemon or socket.

The colours mean:

| Colour | Meaning |
| --- | --- |
| Blue | Bootstrap is running |
| Amber | A reboot is required for log2ram activation |
| Green | Local controller readiness passed |
| Red | Bootstrap or local readiness failed |

Software success is not physical LED acceptance. During live qualification,
observe each colour and record that result separately. The bootstrap command
continues safe host setup if GPIO output is unavailable, while status reports
the GPIO check as failed.

## Installed paths and maintenance

| Path | Purpose |
| --- | --- |
| `/opt/boetticher/releases/<build-id>/` | Immutable installed payload |
| `/opt/boetticher/current` | Active release symlink |
| `/opt/boetticher/venv/` | Private Ansible environment |
| `/opt/boetticher/toolchains/go1.26.5/` | Pinned Go toolchain |
| `/etc/boetticher/controller.yml` | Minimal operator and Blinkt configuration |
| `/var/lib/boetticher/controller/` | Controller state, including the log2ram boot marker |
| `/var/cache/boetticher/` | Downloaded package/toolchain cache |
| `/var/log/boetticher/bootstrap.log` | Bounded bootstrap output |

The playbook enables Debian security-only unattended upgrades and APT timers,
without automatic reboot or automatic Boetticher/Go/Ansible upgrades. It keeps
journald at 32 MiB persistent and 16 MiB runtime limits, and rotates bootstrap
logs daily for seven files.

log2ram uses the signed Azlux Trixie repository with its pinned public key and a
128 MiB RAM-backed `/var/log`. It is not a backup: logs not synchronized before
a sudden power loss can be lost. The native log2ram service and synchronization
timer remain responsible for persistence; bootstrap never forces a live
unmount or reboot.

## Phase-one boundary

This phase prepares only the local controller. Proxmox enrollment, site creation,
Age/SOPS material, PKI, appliance bundles, lab deployment, Companion services,
Kiosk, StreamDeck, and Pulse integration belong to later phases.

The pinned inputs are [Raspberry Pi OS](https://www.raspberrypi.com/documentation/computers/os.html)
Debian 13/Trixie ARM64, [Go 1.26.5](https://go.dev/dl/),
[Ansible Core 2.19.11](https://pypi.org/project/ansible-core/2.19.11/), and
[Azlux log2ram](https://github.com/azlux/log2ram). The Go archive checksum and
Ansible pin are recorded in the repository; the Azlux archive key is shipped as
a public runtime asset.

## Phase two: Proxmox enrollment

After controller readiness passes, Phase two establishes a dedicated root SSH
identity for the existing Proxmox host. The Mac remains the trust bridge: verify
the host key through the Mac's existing strict `known_hosts` relationship, then
copy only that public host key to the Pi. Do not use `ssh-keyscan`, TOFU, or
`StrictHostKeyChecking=no`.

```sh
sudo boetticher host identity create
sudo boetticher host identity public-key
sudo boetticher host trust import --address 192.168.4.5 --key 'ssh-ed25519 VERIFIED_HOST_KEY'
sudo boetticher host enroll root@192.168.4.5
sudo boetticher host status --details
```

From the Mac, first verify the existing relationship without accepting a new
key:

```sh
ssh -o StrictHostKeyChecking=yes root@192.168.4.5 'hostname; pveversion'
```

For an un-hashed, unambiguous entry, copy the exact Ed25519 record from the
Mac's trusted file (do not run `ssh-keyscan`):

```sh
awk '$1 == "192.168.4.5" && $2 == "ssh-ed25519" { print $2 " " $3; exit }' \\
  ~/.ssh/known_hosts
```

If the file is hashed or has multiple ambiguous records, stop and verify the
record manually through the trusted Mac/console rather than guessing. Then
pass only the verified public host key to `host trust import`. To authorize the
Pi, inspect the host's effective `AuthorizedKeysFile` through the trusted Mac
session and append the printed controller public key idempotently to that
existing root key file; do not replace other recovery keys.

`host enroll` performs strict read-only checks with the persistent controller
identity and records only `/etc/boetticher/lab.yml` with the verified address,
root user, node binding, and `no-subscription` repository policy. It does not
create tokens, secrets, PKI, site state, guests, storage, or networking.

`host status` is read-only. `--details` shows existing guests as operator-owned,
Proxmox storage, stable `/dev/disk/by-id` identities, LVM, mounts, and network
facts. It does not adopt or mutate discovered objects. A working but unprepared
host is reported as requiring preparation, not as unhealthy.

`host prepare` displays its bounded change set and requires confirmation (or
`--yes`). Its dedicated Ansible role only configures the known Proxmox
no-subscription repository policy, required host prerequisites, and headless
power behavior. It never formats disks, changes guests, storage, bridges,
addresses, routes, firewall, or recovery access. Re-running it is safe; it does
not upgrade or reboot Proxmox.

The controller keeps the private key at
`/var/lib/boetticher/controller/ssh/id_ed25519` with root-only permissions and
the imported host key at `known_hosts` in the same directory. Independent
Mac/root access remains the recovery path. This phase inventories the dual-disk
host only; disk initialization belongs to a later, explicitly authorized phase.

## Phase 3A: dedicated data storage

Storage qualification is a separate destructive boundary. Start with both
controller and host readiness passing, then review the read-only plan:

```sh
sudo boetticher storage plan
```

The plan traces the running Proxmox root/LVM stack to protect the boot disk and
identifies candidates only through stable `/dev/disk/by-id` paths. Capacity,
enumeration order, and `/dev/sdX` names are not identity. An empty, uniquely
identified Timetec disk is eligible; mounted, partitioned, LVM-backed,
guest-used, Proxmox-used, changed, or ambiguous state fails closed.

First initialization requires the exact freshly rediscovered stable path and
explicit confirmation:

```sh
sudo boetticher storage initialize \
  --device /dev/disk/by-id/<exact-timetec-id> \
  --confirm
```

The operation creates only one LVM PV, `boetticher-vg`, thin pool `data`, and
the Proxmox `boetticher-data` `lvmthin` store with `images,rootdir` content. It
does not create a filesystem or mount, move guests, alter existing storage,
change networking, or begin Phase 3B. The selected stable identity is written
to `/etc/boetticher/lab.yml` only after successful verification.

`storage status` is read-only. Repeating `storage initialize --confirm` on the
exact healthy layout reports that no changes are required; conflicting or
partial layouts are never wiped automatically. A small reversible Proxmox
allocation smoke test is run without creating a guest. Rebooting Proxmox is a
separate explicit approval gate, followed by rechecking the PV, VG, thin pool,
storage registration, guests, and management network. Independent Mac/root
access remains the recovery path if a storage step fails.
