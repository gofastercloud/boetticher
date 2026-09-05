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
| **VLAN 40 SANDBOX** | `10.10.40.0/24` | Internet-only clients, isolated from peers and private networks. |
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

SANDBOX may use only DHCP and its dedicated DNS/NTP at `10.10.40.1` locally.
HOME, the other lab zones, primary DNS/NTP, gateway administration and peers
are denied. Private destinations and spoofed sources are checked before
established-connection acceptance. SANDBOX DNS uses public upstreams, does not
read the gateway host file, and suppresses private lab names and private reverse
lookups. Its NTP service uses public sources, independently of primary DNS/NTP.

The Proxmox bridge boundary binds virtual clients to their configured NIC MAC
and current Kea lease. It blocks peer unicast, ARP, rogue DHCP/RA, multicast and
IPv6 paths; lease permissions expire if the observer cannot refresh them.
It reads guest NIC configuration without adopting or changing user workloads.
Physical clients also require verified switch-port and AP isolation, DHCP
snooping/source protection where applicable, and cross-AP tests. One shared
uplink cannot establish which physical station sent a cloned MAC/IP pair.
Unsupported switch/AP controls therefore cannot receive an isolation acceptance
result, even when virtual and tagged-uplink fixture tests pass.

AirVPN is a selected transit module, not a second default route. Its router
keeps the existing TRANSIT gateway identity and owns the provider handshake,
kill switch, and forwarding lifecycle. The router firewall policy is loaded by
its systemd unit at boot; Ansible reloads it only when the rendered policy
changes, and reload failure leaves forwarding disabled. The module-local DNS
service is started on convergence and restarted only after its configuration
changes. Selected guests retain their existing gateway and use the router's
split DNS/NTP services; direct HOME/WAN, private destinations, and DoH bypass
paths remain denied.

`boetticher firewall diff --live` compares only the Boetticher-owned tables.
The read-only comparison validates the owned chain policies, set definitions
and membership, per-chain rule order, and rule-expression presence/shape, while ignoring
only nftables handles and counter values. Comments are retained as diagnostic
rule identifiers, not as proof by themselves.

Tailnet routing follows the same lifecycle boundary. Its owned nftables unit
loads the boundary at boot and accepts a policy reload only when the reviewed
trusted-client set changes. The Tailscale daemon is restarted only when its
credential/bootstrap hook changes or when recovery is required; an unchanged
convergence does not tear down an established Tailnet session. Backend health,
route approval, client route acceptance, and private split DNS remain separate
live checks.

## Default platform

The default installation creates exactly three Proxmox guests. The Proxmox
host itself is not a guest and uses the fixed management identity
`lab-proxmox-01` at `10.10.99.5` (`https://proxmox.lab.home.arpa:8006`).

| Guest | Address / URL | Job |
| --- | --- | --- |
| `lab-fw-01` | `10.10.99.1` | Managed Debian gateway. |
| `lab-dns-01` | `10.10.10.10` | Blocky, PowerDNS, and Chrony. |
| `lab-monitor-01` | `10.10.10.20` · `https://monitor.lab.home.arpa` | Pulse Community 6.4.1 monitoring. |

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

The Companion is opt-in after the core lab is established. `companion add`
takes the physical `eth0` MAC and derives one fixed identity:

| Field | Fixed value |
| --- | --- |
| Hostname | `lab-display-01` |
| Zone | SERVERS |
| Address | `10.10.20.50` |
| Address source | Kea reservation bound to the supplied `eth0` MAC |

Adding the Companion changes desired state only. A subsequent `deploy` applies
the Kea reservation and permits the enrolled `lab-jump` account to open only
`10.10.20.50:22`. `companion setup` and `companion status` use that route
through the Proxmox bastion; they do not accept an arbitrary Pi address or
expose the rest of SERVERS through the bastion.

The Pi may keep a HOME-side Wi-Fi address for its default route, initial OS
preparation, or recovery. That address is not stored as Boetticher's Companion
identity. Setup installs only the display, StreamDeck, and optional Pulse-agent
capability; the Pi receives no Proxmox credentials. Direct USB permissions are
limited to the configured device identity and unrelated USB configuration is
preserved.

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

The reference three-drive development host keeps Proxmox and the native
maintainer build workspace on its internal NVMe boot disk. Its stable 1 TB
device is reserved for the dedicated Boetticher guest-storage PV/VG/LVM
layout. The failing 2 TB test disk is retired and disconnected before the next
clean installation; it is not part of the supported platform layout.

Enrollment also installs and verifies the headless Proxmox power policy:
lid-close, suspend-key, hibernate-key, and idle actions are ignored, and the
sleep targets are masked. Deliberate poweroff and reboot remain available.

## Access and state

The usual operator loop is:

```text
boetticher init --site-dir ./my-boetticher
boetticher enroll --site ./my-boetticher --bootstrap-address PROXMOX_HOME_IP --operator-key ~/.ssh/id_ed25519.pub --recovery-confirmed --proxmox-ca /path/to/pve-root-ca.pem
boetticher bundle import ./boetticher-0.1.0.tar.gz --site ./my-boetticher
boetticher deploy --site ./my-boetticher
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
exact plan, then creates one temporary root identity whose private material
exists only in memory. Its public key and bounded cleanup targets are recorded
in the immutable operation journal before privileged mutation. Independent
operator/root recovery access is never removed, locked, overwritten, or used
as Boetticher cleanup ownership.

## Release and maintainer builds

Operators use a signed release bundle. The controller verifies the exact
manifest bytes, artifact digests, trust root, and bundle compatibility before
deployment. Optional maintainer evidence may be inspected but is not required
for operator import. Runtime deployment has no image-builder
guest, builder VMID, builder cache lifecycle, or controller-to-builder source
transfer.

Maintainers may use `BOETTICHER_LOCAL_BUILDER_SSH`,
`BOETTICHER_LOCAL_BUILDER_IDENTITY`, and
`BOETTICHER_LOCAL_BUILDER_KNOWN_HOSTS` with `make local-builder-init`,
`make local-image`, and `make local-images` for isolated native/Linux image
construction. The standard workspace at `/var/lib/boetticher/local-builder`
must remain on the build host's root filesystem; the optional
`local-builder-storage-init` path is for a separate maintainer host only. It is
separate from `storage initialize`, which owns the operator's dedicated
Proxmox guest-storage disk. The native build path is development tooling and
does not change the operator lifecycle or substitute for official hosted
release evidence. The official workflow builds the supported artifacts and
assembles a signed bundle from one exact source revision; scans, SBOMs, smoke
output, and provenance remain maintainer evidence attachments. Native
maintainer runs reuse an artifact when its coordinates, signed content digest,
base dependency, and bytes resolve successfully; missing evidence is reported
as `qualification-needed`, while changed effective build inputs or wrong bytes
are `rebuild-needed` and never reused. The release manifest signs the exact
artifact bytes. Release source provenance remains the exact source revision
used for controller and bundle assembly; the effective build-input digest is
the maintainer cache identity.

## Optional-module acceptance

Qualify optional modules one at a time. A completed deployment is followed by
the real module journey: an active process alone does not establish success.
For AirVPN, verify a recent WireGuard handshake, IPv4 tunnel egress, enabled
forwarding after repeated deployment, and blocked direct-WAN fallback. For
Tailscale, verify registration, route approval and client route acceptance, then
exercise both explicitly trusted and untrusted identities. Trusted clients
inherit the same lab-service policy as TRUSTED, including permitted MGMT
administration. HOME, SANDBOX, undeclared services and Internet exit-node use
remain denied. A running daemon or advertised prefix is not route acceptance.
For logging, verify newly received guest journal entries as well as collector
health. Client-certificate rejection is a failed upload, even when both
services are running.

AirVPN-intent checks cover each enabled selected client. HOME and direct core
DNS/NTP attempts must fail independently of successful public traffic through
AirVPN, private DNS through the router to core authoritative DNS, and public
DNS through AirVPN DNS. Direct DNS/DoT and DoH to the configured core public
upstreams are denied. Arbitrary HTTPS can carry other DoH services; the fixed
upstream guard is not a claim of universal DoH detection.

Use the existing network probe testers for the staged live run, including the
second SANDBOX peer probe and `--airvpn` checks. Record the exact deployed
controller/appliance revisions and correlated packet captures. Exercise cold
boot, repeat deployment, bad firewall loads, endpoint failure, tunnel removal,
route loss and pre-existing TCP/UDP flows. Successful public traffic must be
proved separately from each denied destination; a failed probe transport is a
failed test, never evidence of isolation. Physical-to-virtual and cross-AP
results require the actual authorized devices and cannot be inferred from the
local Linux fixture.

Deployment remains separately authorized: retain management on HOME, establish
restrictive controls before opening paths, renew affected DHCP leases, and
invalidate prohibited connection state. Failure must leave restricted paths
blocked. Prior permissive rulesets are diagnostic evidence, not rollback
targets.

ARR acceptance requires its dedicated data-disk storage and application
journeys. Activating storage on an existing single-disk site is a separate
operation; do not initialize an attached disk merely to satisfy a module test.
Printer acceptance requires the selected physical USB printer. Qualify the
external Companion separately after its network reservation and setup.

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
