---
layout: default
title: Controller
section: controller
description: Prepare the local Boetticher Controller.
---

# The local controller

The Controller is the only supported operator entry point. Bootstrap it first,
then use the Host commands below to enroll, apply, inspect, and recover the
Proxmox Host.

## Supported starting point

Use Raspberry Pi OS Lite based on Debian 13 (Trixie) with the 64-bit ARM64
userspace on a Raspberry Pi 3, 4, or 5-class board. Keep the existing hostname,
network placement, routes, SSH host keys, operator keys, and `pi` passwordless
sudo access unchanged. Test a new public-key SSH session before running the
installer; `--confirm-key-login` records that acknowledgement before password
authentication is disabled.

### Dual-homed Controller DNS

When the Controller has a LAB connection, accept that connection's DHCP DNS
and prefer it for resolving private service names. On NetworkManager, identify
the active connection by its LAB NIC MAC and reservation, rather than assuming
an interface name. Set that connection's `ipv4.ignore-auto-dns` to `no` and use
a lower positive `ipv4.dns-priority` than HOME (the reference setup uses `50`).
Reapply the connection and verify the resolver order. Keep HOME DNS as fallback
and retain HOME's default route; the LAB connection remains `never-default`.
These are Controller-local connection settings, separate from the DNS records
owned by `/etc/boetticher/lab.yml`.

## Install from a local payload

The maintainer payload contains a prebuilt ARM64 `boetticher` binary, its
private Ansible playbook and roles, the pinned Azlux public key, an installer,
and `SHA256SUMS`. It contains no site, credential, appliance, or
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
Ansible, or change Blinkt. The status daemon may contact the enrolled Host for
its lightweight health, update, and connectivity checks.

The controller installs Go 1.26.6 under
`/opt/boetticher/toolchains/go1.26.6/` and Ansible Core 2.19.11 in
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

## Controller status LEDs

The Controller runs one local `boetticher-status.service` daemon. It is the
exclusive owner of the Pimoroni Blinkt and its GPIO23/GPIO24 path; bootstrap and
Host operations send best-effort progress events over its root-only Unix socket
at `/run/boetticher/status.sock`. If the socket or hardware is unavailable,
the operation continues normally.

Controller bootstrap always installs the status daemon and its packaged driver.
Blinkt is optional hardware: if it is absent, the daemon remains installed and
running without a display, and the GPIO check is reported as `NOT TESTED` rather
than blocking Controller readiness. Host apply always installs the packaged
Host speedtest helper; it does not depend on Blinkt or StreamDeck hardware.

The current 4E status layout, viewed from the operator side, is:

```text
CTL HOST FW VPN TAILNET NET CTRL-UPDATES HOST-UPDATES
```

DHCP/NTP and independent DNS detail remain available through the existing
StreamDeck detail view and CLI status.

| Display | Meaning |
| --- | --- |
| Breathing green | The lightweight check is healthy |
| Steady blue | Startup or checking |
| Pulsing amber | Attention or degraded operation |
| Solid red | A meaningful health or operation failure |
| Off | Not configured or not applicable |

Apply and test commands temporarily use dedicated operation modes. Apply shows
the blue Knight Rider chase while it is running, then holds an all-green or
all-red result briefly. Test shows one pixel per named test group: active tests
pulse blue, passed tests are solid green, and failed tests are solid red. The
current firewall test uses five groups (gateway, Internet egress, inter-zone
policy, HOME protection, and administration). The final result is held briefly
before Standard status resumes. Display notifications remain best-effort and
never affect the command result.

`CTL` is local Controller health and `HOST` is the enrolled Proxmox Host.
`FW` is the firewall capability's native status result; `DHCP/NTP` is the
shared client-service native status result. `Tailnet` is the fixed
subnet-router's native local status; it does not represent remote packet
qualification. Amber means action
required, blue means configuration staged or an operation is in progress, and
green means healthy. These are operational display states, not packet
qualification evidence.
`CTRL-UPDATES` is green when no Controller updates are available, amber when
updates or the native `/var/run/reboot-required` marker require attention, and
blue when an explicit Boetticher configuration-staged event is active.
`HOST-UPDATES` is green when no Proxmox package updates or Host reboot are
reported, and amber when either is reported. Both update views are read-only;
they do not run package installation, refresh package lists, or reboot.

`NET` runs a lightweight Host-side ping/connectivity check every 60 seconds.
It is green when Host Internet connectivity is available and the most recent
full speedtest download meets the configured threshold. It is amber when
connectivity works but the speedtest is below the threshold or has no usable
recent result, and red only after connectivity fails twice consecutively. The
full speedtest runs from the Host approximately every hour using the
release-built `showwin/speedtest-go` helper on `vmbr0`; the reference-lab
threshold is 500 Mbps for its approximately 1000 Mbps service.

The optional configuration keeps these defaults explicit without adding a
status database or generated state:

```yaml
status:
  interval: 30s
  ping_interval: 60s
  internet:
    throughput_interval: 1h
    healthy_mbps: 500
  blinkt:
    enabled: true
    brightness: 0.3
  streamdeck:
    enabled: true
    brightness: 0.5
    telemetry_interval: 15s
```

The display is a lightweight operator convenience, not authoritative
monitoring or qualification. A green LED means only that its corresponding
simple, read-only check passed. It has no dependency on Pulse, Prometheus,
Loki, Alertmanager, Gatus, a monitoring database, or an external monitoring
API. The hourly speedtest uses the external speedtest.net measurement service
only for that explicit performance sample. The Controller daemon runs with
root privileges in the reference image because the GPIO device is root-owned;
its systemd unit otherwise confines network, filesystem, and device access.
An external Companion's optional StreamDeck service is installed only when its
capability is enabled and retries until the configured USB device is present;
its absence does not block Companion setup.

When a StreamDeck is attached to the Controller, it is owned by the same
`boetticher-status.service` daemon as Blinkt. The home screen is a detailed,
read-only view of the enrolled Host. Its five-key rows are Proxmox health
(`PVE`, CPU, RAM, DATA, NET), five VM/LXC guests sorted by VMID, and core
services (`FW`, VPN, TAILNET, SCROLL, REFRESH). DATA follows fresh/stale Host
telemetry; VPN currently renders `OFF` because the status snapshot has no VPN
mapping, which is a display gap rather than proof that VPN is absent. SCROLL cycles
through guests five at a time. Each guest tile uses `VM<id>` or `CT<id>` on
the first line, the hostname on the second, and its runtime status on the
third.
Host and guest detail views provide BACK and REFRESH only; StreamDeck input
cannot start, stop, reboot, deploy, or run shell commands. The old standalone
Controller StreamDeck service is removed during Controller bootstrap.

The Host detail view also shows `FW`, `DHCP`, and `TAILNET` using the same coarse
component states as Blinkt. `FW` consumes the native `module firewall status`
result; the client-service slot consumes `module dhcp status`, and TAILNET
consumes `module tailnet status`. Unconfigured is off, while a
configured-but-unavailable service is failed.

## Installed paths and maintenance

| Path | Purpose |
| --- | --- |
| `/opt/boetticher/releases/<build-id>/` | Immutable installed payload |
| `/opt/boetticher/current` | Active release symlink |
| `/opt/boetticher/venv/` | Private Ansible environment |
| `/opt/boetticher/toolchains/go1.26.6/` | Pinned Go toolchain |
| `/etc/boetticher/controller.yml` | Minimal operator and Blinkt configuration |
| `/var/lib/boetticher/controller/` | Controller state, including the log2ram boot marker |
| `/run/boetticher/status.sock` | Root-only best-effort operation event socket |
| `/var/cache/boetticher/` | Downloaded package/toolchain cache |
| `/var/log/boetticher/bootstrap.log` | Bounded bootstrap output |
| `/var/log/boetticher/operations.log` | Bounded underlying host-operation output |

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

This phase prepares the Controller and the Proxmox Host. Firewall,
platform guests, physical trunks, and application modules belong to later
phases. No alternate workstation, TUI, kiosk, or Companion bootstrap path is
supported.

The pinned inputs are [Raspberry Pi OS](https://www.raspberrypi.com/documentation/computers/os.html)
Debian 13/Trixie ARM64, [Go 1.26.6](https://go.dev/dl/),
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
sudo boetticher host create-identity
sudo boetticher host show-public-key
sudo boetticher host import-host-key --address 192.168.4.5 --key 'ssh-ed25519 VERIFIED_HOST_KEY'
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
pass only the verified public host key to `host import-host-key`. To authorize the
Pi, inspect the host's effective `AuthorizedKeysFile` through the trusted Mac
session and append the printed controller public key idempotently to that
existing root key file; do not replace other recovery keys.

`host enroll` performs strict read-only checks with the persistent controller
identity and records only `/etc/boetticher/lab.yml` with the verified address,
root user, node binding, and `no-subscription` repository policy. It does not
create API tokens, application secrets, PKI, guests, storage, or networking.

`host status` is read-only. `--details` shows existing guests as operator-owned,
Proxmox storage, stable `/dev/disk/by-id` identities, LVM, mounts, and network
facts. It does not adopt or mutate discovered objects. A working but unprepared
host is reported as requiring preparation, not as unhealthy.

`host apply` displays its bounded Host change set and requires confirmation (or
`--yes`). Its dedicated Ansible role only configures the known Proxmox
no-subscription repository policy, required host prerequisites, and headless
power behavior, and the signed release-built Host speedtest helper. It never
formats disks, changes guests, storage, bridges, addresses, routes, firewall, or
recovery access. Re-running it is safe; it does not upgrade or reboot Proxmox.
The required Proxmox services (`pve-cluster`, `pvedaemon`, `pvestatd`, and
`pveproxy`) are explicitly enabled and started by the same Host setup role so
they return after reboot.

The controller keeps the private key at
`/var/lib/boetticher/controller/ssh/id_ed25519` with root-only permissions and
the imported host key at `known_hosts` in the same directory. Independent
Mac/root access remains the recovery path. This phase inventories the dual-disk
host only; disk initialization belongs to a later, explicitly authorized phase.

## Phase 3A: dedicated data storage

Storage initialization is a separate destructive boundary. Start with both
controller and host readiness passing, then review the read-only plan:

```sh
sudo boetticher host plan-storage
```

The plan traces the running Proxmox root/LVM stack to protect the boot disk and
identifies candidates only through stable `/dev/disk/by-id` paths. Capacity,
enumeration order, and `/dev/sdX` names are not identity. An empty, uniquely
identified Timetec disk is eligible; mounted, partitioned, LVM-backed,
guest-used, Proxmox-used, changed, or ambiguous state fails closed.

First initialization requires the exact freshly rediscovered stable path and
explicit confirmation:

```sh
sudo boetticher host apply \
  --data-disk /dev/disk/by-id/<exact-data-disk-id> \
  --yes
```

The operation creates only one LVM PV, `boetticher-vg`, thin pool `data`, and
the Proxmox `boetticher-data` `lvmthin` store with `images,rootdir` content. It
does not create a filesystem or mount, move guests, alter existing storage,
change networking, or begin Phase 3B. The selected stable identity is written
to `/etc/boetticher/lab.yml` only after successful verification.

`host status` is read-only. Repeating `host apply --yes` on the
exact healthy layout reports that no changes are required; conflicting or
partial layouts are never wiped automatically. During live acceptance, run a
small reversible Proxmox allocation smoke test without creating a guest.
Rebooting Proxmox is a separate explicit approval gate, followed by rechecking
the PV, VG, thin pool, storage registration, guests, and management network.
Independent Mac/root access remains the recovery path if a storage step fails.

## Phase 3B: Host virtual networking

Phase 3B adds only the internal virtual bridge. It preserves the proven HOME
management path and does not configure a physical trunk or any routing policy:

```text
HOME
  |
  +-- physical HOME NIC
         |
       vmbr0
         |
         +-- Proxmox 192.168.4.5

Virtual LAB
  |
  +-- vmbr1   VLAN-aware, nic1 tagged member (VLAN 5/10/20/30/40/99)
       |
       +-- VLAN 5   TRANSIT
       +-- VLAN 10  INFRA
       +-- VLAN 20  SERVERS
       +-- VLAN 30  TRUSTED
       +-- VLAN 40  SANDBOX
       +-- VLAN 99  MGMT
```

Review the protected path before configuration:

```sh
sudo boetticher host apply --adopt-existing-network --yes
sudo boetticher host status
```

`host status` is read-only. `host apply` adds an absent `vmbr1` stanza with VLAN
awareness and no untagged address or gateway. The accepted physical binding is
the verified `nic1` MAC `a0:ce:c8:a2:b2:10`, restricted to tagged VLANs
5/10/20/30/40/99 with untagged ingress rejected. Host management uses tagged
`vmbr1.99` at `10.10.99.5/24`, with LAB return routes via `10.10.99.1`. It
never rewrites `vmbr0`, changes `192.168.4.5`, changes the default route,
enables forwarding,
or configures DHCP, DNS, firewall, guests, or switches. An unknown or
conflicting `vmbr1` or physical binding is reported and not adopted.

A compatible existing bridge requires explicit adoption:

```sh
sudo boetticher host apply --adopt-existing-network --yes
```

The command displays the protected HOME path and runtime addresses before
asking for confirmation (or accepts `--yes` for deliberate scripted use).
Adoption requires a VLAN-aware bridge with no configured addresses,
gateway, or unknown interface directives. Runtime IPv6 link-local addresses
alone are compatible; configured link-local, global IPv6, IPv4, and gateway
routes remain conflicts.

Boetticher owns `/etc/sysctl.d/70-boetticher-vmbr1.conf`, setting
`net.ipv6.conf.vmbr1.disable_ipv6=1`, and a vmbr1-only
`/etc/network/if-up.d/boetticher-vmbr1` hook. The hook reapplies suppression
after bridge creation, including at boot; configuration requires ifupdown2
script support to be enabled. Existing unrelated files at either path are
rejected. This disables host IPv6 participation on vmbr1 without adding any
Ethernet filtering or globally disabling IPv6.

After configuration and again after an explicitly authorized Proxmox reboot,
verify:

```sh
ip -6 addr show dev vmbr1
sysctl net.ipv6.conf.vmbr1.disable_ipv6
```

There must be no IPv6 address and the sysctl must equal `1`. Verify fresh
Pi-to-Proxmox SSH, unchanged vmbr0/nic0/192.168.4.5/default route, no vmbr1 host
IPv4 or physical ports, VLAN awareness, repeat configure with no changes, and
`host status` PASS. The current reference architecture is IPv4-only; guest IPv6
forwarding is not a Host acceptance claim. The retained guest bridge regression
is internal to vmbr1, while IPv6 forwarding and security policy belong to
explicit future firewall/network Module work.

The six VLAN numbers remain logical desired configuration for later guest
deployment. They do not claim zone isolation in this phase. Configuration is
revalidated through a fresh strict Controller SSH session, and repeat runs on
an exact bridge report that no changes are required. Proxmox reboot is a
separate explicit gate; the independent Mac/root path is the recovery method
if management verification fails. Phase 3B stops before firewall deployment.

## Host teardown and rebuild

Host configuration has a bounded inverse for qualification and recovery:

```sh
sudo boetticher host teardown --plan
sudo boetticher host teardown \
  --data-disk /dev/disk/by-id/EXACT_DATA_DISK --yes
```

The plan preserves the Controller identity, trusted Proxmox host key,
Proxmox installation, boot storage, and HOME management. It removes only exact
Boetticher-owned vmbr1, its host IPv6 suppression, the `boetticher-data`
registration and LVM layout, safely removable host-baseline files, and the
enrollment, storage, and network selections in `lab.yml`. Shared packages,
unknown repository or power settings, guests, and unrelated storage stop the
operation.

Teardown is ordered from dependent Host configuration to its prerequisites and is retryable by rerunning
the same command. The exact Timetec stable path is required for disk
destruction; `--yes` confirms only non-destructive prompts. After remote work
succeeds, `lab.yml` retains the Proxmox address and user but omits the enrolled
node, storage, and network selections. `host status` then reports the
intentional trust-only state and `host apply` directs the operator to
`host enroll`.

Approved reboot rehearsals are also Controller operations:

```sh
sudo boetticher host reboot --yes
sudo boetticher controller reboot --yes
```
