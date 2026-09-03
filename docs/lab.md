---
layout: default
title: The lab
section: lab
description: The Boetticher network, platform guests, access routes, storage, recovery, and physical lab contract.
---

# Your lab, demystified

Boetticher manages a deliberately small platform around your Proxmox
workloads. The default topology is virtual-only: `vmbr0` remains on HOME and
`vmbr1` is a VLAN-aware internal bridge with no physical member.

## Fixed network

The managed gateway is `lab-fw-01` at `10.10.99.1`. It owns routing, NAT,
Kea DHCP/DDNS, nftables, and the zone boundary. Blocky answers client DNS;
PowerDNS owns the private names; Chrony supplies NTP.
The managed gateway appliance is pinned to
`debian-13-genericcloud-amd64-20260327-2429`.

| Zone | Network | Purpose |
| --- | --- | --- |
| **VLAN 5 TRANSIT** | `10.10.5.0/24` | Transit services, including optional AirVPN. |
| **VLAN 10 INFRA** | `10.10.10.0/24` | DNS, NTP, and monitoring. |
| **VLAN 20 SERVERS** | `10.10.20.0/24` | Reserved-address servers and applications. |
| **VLAN 30 TRUSTED** | `10.10.30.0/24` | Trusted client devices. |
| **VLAN 40 SANDBOX** | `10.10.40.0/24` | Disposable devices and experiments. |
| **VLAN 99 MGMT** | `10.10.99.0/24` | Proxmox and gateway management. |

The default single-port installation requires no switch change. A physical
trunk is an explicit advanced choice and carries VLANs 5, 10, 20, 30, 40,
and 99. Keep HOME on `vmbr0`; do not move the existing management member to
the internal bridge.

```text
boetticher network trunk status --site ./my-boetticher --live
boetticher network trunk attach IFACE --live --confirm --site ./my-boetticher
```

The trunk operation verifies the observed interface and permanent hardware
identity before changing the Proxmox bridge. Detach is equally explicit.

## Default platform

The default installation creates exactly three Proxmox guests. The Proxmox
host itself is not a guest and uses the fixed management identity
`lab-proxmox-01` at `10.10.99.5` (`https://proxmox.lab.home.arpa:8006`).

| Guest | Address / URL | Job |
| --- | --- | --- |
| `lab-fw-01` | `10.10.99.1` | Managed Debian gateway. |
| `lab-dns-01` | `10.10.10.10` | Blocky, PowerDNS, and Chrony. |
| `lab-monitor-01` | `10.10.10.20` · `https://monitor.lab.home.arpa` | Pulse Community 6.1.2 monitoring. |

DNS2 is not a default guest because two guests on one Proxmox host share the
same physical host, storage, power, and network failure domains. A second DNS
guest would add operational work without providing host-level resilience.

Central logging is an optional module and is off by default. Gatus is also an
optional module; it is not part of the core status path. Pulse remains because
it supplies historical telemetry, Proxmox and guest health, an externally
consumable health API, and the Companion integration without placing Proxmox
credentials on the Companion. Pulse access is scoped and read-only.

Core platform guests use the `100–199` guest range. Optional modules use the
`200–499` guest range. Your workloads use
`500–899`. Boetticher never adopts or deletes an unknown VM, LXC, volume, or
network device merely because its name or address looks familiar.

## Companion Pi placement

The Companion is outside the Proxmox module model. In the physical lab layout:

* the Proxmox second NIC connects to a tagged switch trunk carrying VLANs 5,
  10, 20, 30, 40, and 99;
* the Pi's `eth0` connects to an untagged SERVERS access port, VLAN 20;
* `wlan0` connects to HOME and remains the Pi's default route; and
* `eth0` carries the deterministic route to the lab networks and Pulse.

The Pi's SERVERS address should be a DHCP reservation. The Companion setup
installs only the display, StreamDeck, and optional Pulse-agent capability;
the Pi receives no Proxmox credentials. Direct USB permissions are limited to
the configured device identity and unrelated USB configuration is preserved.

## Storage and headless operation

The single-disk profile is the default. The dedicated-data-disk profile uses
the exact stable `/dev/disk/by-id/` identity selected during initialization
and creates the Boetticher-owned LVM layout:

| Name | Job |
| --- | --- |
| `vg_boetticher` | Volume group on the selected data disk. |
| `boetticher-thin` | Thin storage for guest images and filesystems. |
| `boetticher-backups` | Local backup storage. |

Use `storage initialize` only after reviewing the exact device. It is the
guarded destructive operation for a disposable, known-owned layout.

Enrollment also installs and verifies the headless Proxmox power policy:
lid-close, suspend-key, hibernate-key, and idle actions are ignored, and the
sleep targets are masked. Deliberate poweroff and reboot remain available.

## Access and state

The usual operator loop is:

```text
boetticher init --site-dir ./my-boetticher
boetticher enroll --site ./my-boetticher --bootstrap-address PROXMOX_HOME_IP --operator-key ~/.ssh/id_ed25519.pub --recovery-confirmed --proxmox-ca /path/to/pve-root-ca.pem
boetticher bundle import ./boetticher-0.5.1.tar.gz --site ./my-boetticher
boetticher plan --site ./my-boetticher --live --json
boetticher deploy --plan sha256:PLAN_DIGEST --site ./my-boetticher
boetticher status --site ./my-boetticher --details --live
```

`status --details` is the consolidated read-only operational view. It never
repairs infrastructure. `module configure`, reservations, and `update` alter
desired state only; `deploy` is the normal live mutation boundary.

Boetticher keeps four authoritative state classes:

1. desired state: what the operator requested;
2. observed state: read-only facts from the controller and target;
3. immutable operation state: the approved plan and bounded Apply journal; and
4. last-applied state: the plan and model revision that completed successfully.

Ansible inventory, DNS, firewall, SSH, and service files are deterministic,
disposable projections. They can be regenerated from desired state and are
not alternate configuration authorities.

The trust lifecycle distinguishes three identities. Enrollment stores durable
read-only/scoped Proxmox API authority. Apply re-observes and accepts the
exact plan, then creates one in-memory temporary root identity for bounded
privileged mutation and cleanup. Independent operator/root recovery access is
never removed, locked, overwritten, or used as Boetticher cleanup ownership.

## Release and maintainer builds

Operators use a signed release bundle. The controller verifies the exact
manifest bytes, artifact digests, trust root, qualification evidence, and
bundle compatibility before deployment. Runtime deployment has no image-builder
guest, builder VMID, builder cache lifecycle, or controller-to-builder source
transfer.

Maintainers may use `BOETTICHER_LOCAL_BUILDER_SSH`,
`BOETTICHER_LOCAL_BUILDER_IDENTITY`, and
`BOETTICHER_LOCAL_BUILDER_KNOWN_HOSTS` with `make local-builder-init`,
`make local-image`, and `make local-images` for isolated native/Linux image
construction. Set `BOETTICHER_LOCAL_BUILDER_DEVICE` to the exact stable build
disk and run `make local-builder-storage-init` once to create and persist the
mount at `/var/lib/boetticher/local-builder`. This maintainer-only initializer
is separate from `storage initialize`, which owns the operator's dedicated
Proxmox data disk. The native build path is development tooling and does not
change the operator lifecycle or substitute for official hosted release
evidence. The official workflow builds all
supported artifacts, scans and qualifies their final bytes, binds evidence to
those bytes, and assembles the signed bundle from one exact source revision.

## Recovery

Keep the private site repository, independent Age identity, certificate
material, and off-host backups separate from the Proxmox host. Start recovery
with the read-only view:

```text
boetticher status --site ./my-boetticher --details --live
boetticher plan --site ./my-boetticher --live --json
```

Use `boetticher recover` only for its documented, exact recovery target.
Unknown guests and storage are not cleanup targets. Reinstalling the boot disk
does not authorize reinitializing the separate data disk; select the same
stable device deliberately and use `--reinitialize` only for known disposable
Boetticher state.
