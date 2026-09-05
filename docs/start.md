---
layout: default
title: Start here
section: start
description: Set up a fresh Boetticher lab, then settle into the day-to-day rhythm.
---

# Start here

Boetticher starts from a fresh, supported amd64 Proxmox VE installation. You
also need a macOS or Linux controller with the Boetticher binary, SSH, and
Ansible Core; the Proxmox HOME address; its API CA certificate; and a private
site directory.

The default setup is virtual-only and requires no switch change. HOME remains
on `vmbr0`; the internal VLAN-aware `vmbr1` has no physical member. The
fixed network still uses VLANs 5, 10, 20, 30, 40, and 99. Attach a physical
trunk only through the guarded advanced command documented in the
[lab guide](lab.html).

## Install and enroll

Replace `PROXMOX_HOME_IP`, the public-key path, and the certificate path with
your values. The operator public-key file must match the private identity used
to reach the fresh host. Enrollment records the observed Proxmox identity,
creates durable scoped API access, configures the bastion and headless power
policy, and does not arm deployment-only root access.

```text
boetticher init --site-dir ./my-boetticher
boetticher enroll --site ./my-boetticher   --bootstrap-address PROXMOX_HOME_IP   --operator-key ~/.ssh/id_ed25519.pub   --recovery-confirmed   --proxmox-ca /path/to/pve-root-ca.pem
```

The Proxmox installer hostname does not need to be a special Boetticher name.
The enrollment path discovers the one standalone Proxmox node returned by the
host and API, then binds live operations to that observed node. Keep the
hostname stable after enrollment.

If the site uses the dedicated-data-disk profile, initialize the exact stable
device after reviewing it:

```text
boetticher init --site-dir ./my-boetticher   --storage-profile dedicated-data-disk   --storage-device /dev/disk/by-id/DEVICE
boetticher storage initialize --site ./my-boetticher --storage-confirmed
```

Initialization is the guarded destructive path for the selected device. It
does not format an unspecified disk or an unknown Proxmox workload.

## Deploy a signed release

Operators consume built artifacts; the normal deployment path has no image
builder guest or runtime builder cache. Import the signed release bundle,
review its live plan, apply exactly that digest, and inspect the result:

```text
boetticher bundle import ./boetticher-0.1.0.tar.gz --site ./my-boetticher
boetticher deploy --site ./my-boetticher
boetticher status --site ./my-boetticher --details --live
```

The controller rejects stale or mismatched plan digests before temporary Apply
authority is acquired. A successful deployment revokes that temporary identity
before recording last-applied state.

## Local maintainer image builds

Image construction remains available for maintainers on a native Linux build
host, isolated from the operator lifecycle. On macOS, configure the explicit
SSH route first. The standard workspace is
`/var/lib/boetticher/local-builder` on the build host's root filesystem:

```text
export BOETTICHER_LOCAL_BUILDER_SSH=root@BUILD_HOST
export BOETTICHER_LOCAL_BUILDER_IDENTITY=/path/to/operator-key
export BOETTICHER_LOCAL_BUILDER_KNOWN_HOSTS=/path/to/build-host-known_hosts
make local-builder-init
make local-image LOCAL_IMAGE_TARGET=image-firewall
make local-images LOCAL_IMAGE_TARGETS="image-dns-blocky image-monitoring"
```

The optional `local-builder-storage-init` path is only for a separate
maintainer host that deliberately keeps a dedicated build disk. It is not part
of this lab layout and must never target the Proxmox guest-storage disk.

The native host keeps its downloads, build root, cache, and generated
maintainer artifacts on the root filesystem. These targets are useful for local
iteration; they do not create Proxmox guests and do not replace the official
hosted build, scan, qualification, signed-bundle, and exact-source release
gates.

Qualified artifacts are reusable when their artifact coordinates, signed
content digest, base dependency, and bytes still match. Controller,
documentation, test, release-import, and maintainer-wrapper changes do not
force unrelated image reconstruction. The release manifest signs the exact
artifact bytes; source and build-definition revisions remain provenance, not a
runtime rebuild trigger. Missing maintainer evidence is reported separately
and does not force image reconstruction.

For a three-drive development machine, keep the operating system on the
internal NVMe boot drive, put the persistent Linux build root, downloads,
caches, and generated maintainer artifacts there, and use the stable 1 TB drive
as the dedicated Proxmox guest-storage PV/VG/LVM store. The failing 2 TB drive
is retired after its guests are removed. This is a maintainer layout. A normal operator
chooses the one- or two-disk storage profile and downloads qualified release
artifacts; they do not need this local build arrangement.

## Optional modules and the Companion

The default Proxmox platform is the firewall, one DNS/NTP guest, and Pulse
monitoring. Logging is optional and off by default. Gatus is optional and is
not required for platform health. Pulse remains narrow: historical telemetry,
Proxmox and guest health, a health API, and the read-only Companion
integration.

```text
boetticher module list --site ./my-boetticher
boetticher module configure gatus --site ./my-boetticher
boetticher plan --site ./my-boetticher --live --json
boetticher deploy --plan sha256:PLAN_DIGEST --site ./my-boetticher
boetticher status --site ./my-boetticher --details --live
```

The Companion Pi is external to the Proxmox module model. In the physical lab
it uses `eth0` on the SERVERS access port (VLAN 20) and `wlan0` on HOME as
the default route. The Proxmox second NIC is the tagged internal trunk. See
the [lab guide](lab.html) for the exact physical contract and switch
implications.

### Add the optional Companion

Finish the core deployment and confirm `status --details --live` first. Attach
the separately guarded Proxmox physical trunk, then connect the Pi's `eth0` to
an untagged SERVERS port and record that physical interface's MAC:

```text
boetticher companion add --mac COMPANION_ETH0_MAC --dry-run --site ./my-boetticher
boetticher companion add --mac COMPANION_ETH0_MAC --confirm --site ./my-boetticher
boetticher deploy --site ./my-boetticher
boetticher companion setup --dry-run --site ./my-boetticher
boetticher companion setup --host-key 'ssh-ed25519 VERIFIED_HOST_KEY' --confirm --site ./my-boetticher
boetticher companion status --site ./my-boetticher
```

For a Pi fitted with Blinkt, add `--blinkt=true` to `companion add`. Use
`--display=false` or `--streamdeck=false` when that hardware is not fitted.
The default screen is a local read-only dashboard controlled from StreamDeck;
no mouse, keyboard, touchscreen, or browser login is required. Run platform
`deploy` after changing the Companion configuration so its dedicated Pulse
credentials are prepared before `companion setup`.

`companion add` changes desired state only. It derives `lab-display-01` at
`10.10.20.50` on SERVERS; the following `deploy` applies that Kea reservation,
DDNS identity, and the exact Proxmox-bastion route. Setup and status then use
that address automatically. They do not accept an arbitrary target address.

The Pi may retain HOME Wi-Fi as its default route, but a temporary HOME address
is bootstrap or recovery context only. Boetticher neither saves it nor uses it
as the managed Companion identity. Supply `--host-key` on the first setup only
after independently verifying the Pi's SSH host key.

## Everyday operations

This controller pins Pulse server and agents to 6.4.1. For an existing site
that pins 6.1.2, run `boetticher update --dry-run --site ./my-boetticher`, then
`boetticher update --confirm --site ./my-boetticher`. This updates desired state
only. Import a matching new signed release containing monitoring image 1.0.1,
then deploy to update Pulse and install the module-local VPN sensors. Repeat
`companion setup` to update the Pi agent and displays. Do not use the Pulse
self-updater to bypass the appliance release selection.

Use the consolidated read-only view first:

```text
boetticher status --site ./my-boetticher --details --live
boetticher plan --site ./my-boetticher --live --json
```

Change desired state with `module configure`, reservations, or `update`,
then deploy the reviewed plan. Use `boetticher recover` only for its named,
exact recovery target. Preserve the independent Age identity, operator/root
recovery path, certificate material, and off-host backups.
