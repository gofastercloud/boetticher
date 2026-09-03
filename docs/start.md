---
layout: default
title: Start here
section: start
description: Set up a fresh Boetticher lab, then settle into the day-to-day rhythm.
---

# Start with a fresh host and a cup of something good

Boetticher starts from a fresh, supported Proxmox VE installation on amd64 hardware. You will also need a macOS or Linux controller with the Boetticher binary, SSH, and Ansible Core; the current HOME-side address for Proxmox; its root CA certificate; and a private place for your site directory.

The default virtual-only setup needs one Ethernet port. Version 0.5.0 does not remove or renumber any VLANs, and it does not ask you to reconfigure the switch for a normal fresh install. A physical VLAN trunk or an external firewall needs a second port and a VLAN-aware switch when you are ready for that bigger experiment.

The 0.5.0 rhythm is pleasantly deliberate: import the signed release bundle,
make a live plan, deploy the exact digest you reviewed, then check the lab.
StreamDeck is now an external companion-Pi capability, so a new install does
not create a StreamDeck guest in Proxmox.

## Fast local image iteration

The controller and source checks run quickly on macOS. Appliance image
construction needs Linux root, `mmdebstrap`, and libguestfs, so use the
persistent local builder for focused image work:

```text
make local-builder-init
make local-image LOCAL_IMAGE_TARGET=image-firewall
make local-images LOCAL_IMAGE_TARGETS="image-dns-blocky image-monitoring"
```

On macOS, `local-builder-init` creates an amd64 OrbStack Ubuntu builder and
keeps verified downloads and the base rootfs in its persistent Linux cache.
The local targets are for development iteration; the full image build,
Trivy qualification, signed bundle, and release publication still run in the
official CI workflow.

If an x86 firewall image build is too slow under Apple Silicon emulation, use
a native amd64 Linux host instead. The source checkout is copied to a fixed
builder directory, while the cache stays on that host:

```text
BOETTICHER_LOCAL_BUILDER_MODE=ssh BOETTICHER_LOCAL_BUILDER_SSH=root@192.0.2.73 make local-builder-init
BOETTICHER_LOCAL_BUILDER_MODE=ssh BOETTICHER_LOCAL_BUILDER_SSH=root@192.0.2.73 make local-image LOCAL_IMAGE_TARGET=image-firewall
```

The SSH builder receives source files only; it does not receive the private
site directory or encrypted secrets. Use a dedicated native Linux builder
where possible rather than installing build tooling on a production host.

For a reinstallable three-drive Proxmox host, keep the operating system on the
boot disk, mount the separate build disk at `/var/lib/boetticher/local-builder`,
and keep the appliance data layout on the dedicated data disk. The build disk
holds the native builder root, downloads, caches, and generated artifacts; the
data disk is managed by the site’s `dedicated-data-disk` profile and survives a
boot-disk reinstall.

## The happy path

Replace <code>PROXMOX_HOME_IP</code> and the certificate path with your real values. The HOME address is the one your existing router gave Proxmox; it is not a new lab address.

```text
boetticher init --site-dir my-boetticher
boetticher bootstrap-endpoint set PROXMOX_HOME_IP --site my-boetticher
boetticher preflight --site my-boetticher --live
boetticher bootstrap --site my-boetticher --recovery-confirmed --proxmox-ca /path/to/pve-root-ca.pem
boetticher bundle import ./boetticher-0.5.0.tar.gz --site my-boetticher
boetticher plan --site my-boetticher --live --json
boetticher deploy --plan sha256:PLAN_DIGEST --site my-boetticher
boetticher status --site my-boetticher --live
```

`init` makes your little private site repository and its age recovery identity. Keep an independent copy of that identity somewhere sensible before you need it. If you choose the dedicated-data storage profile, pause at the confirmation and make sure the selected disk really is the spare one.

Select and initialize the dedicated data disk through Boetticher so its stable
identity, fixed LVM layout, Proxmox storage IDs, and backup mount are recorded
together:

```text
boetticher init --site-dir my-boetticher --storage-profile dedicated-data-disk --storage-device /dev/disk/by-id/DEVICE
boetticher storage initialize --site my-boetticher --storage-confirmed
```

Use `--reinitialize` only when the exact existing `vg_boetticher` layout is
known to be disposable previous-test state. It refuses configured guests and
conflicting storage definitions before erasing the Boetticher-owned layout.

<aside class="callout">
  <p><strong>Bring your own firewall?</strong> Add <code>--external-firewall</code> to <code>init</code>, then select and record the physical trunk explicitly during live preflight and bootstrap:</p>
  <pre><code>boetticher preflight --site my-boetticher --live --record --trunk-interface IFACE
boetticher bootstrap --site my-boetticher --recovery-confirmed --proxmox-ca /path/to/pve-root-ca.pem --trunk-interface IFACE</code></pre>
  <p>Your appliance must provide the six VLANs, gateway addresses, DHCP where applicable, DNS/NTP routes, NAT, and zone separation. That is a proper architectural handoff, not a cosmetic setting; the <a href="lab.html#when-you-want-to-go-bigger">lab guide</a> has the compact contract.</p>
</aside>

## Your everyday rhythm

Once the lab is up, the regular loop stays boring in the best possible way:

```text
boetticher plan --site ./my-boetticher --live --json
boetticher deploy --plan sha256:PLAN_DIGEST --site ./my-boetticher
boetticher status --site ./my-boetticher --live
boetticher doctor --site ./my-boetticher --live
```

Without <code>--live</code>, a command reads the site directory on your controller. With it, the command also asks the running lab what is happening. <code>status --live</code> is the quick “is the lab okay?” view; <code>doctor --live</code> is the useful “what should I do next?” companion.

To add something new, configure it first and deploy when you like the plan:

```text
boetticher module list --site ./my-boetticher
boetticher module configure gatus --site ./my-boetticher
boetticher plan --site ./my-boetticher --live --json
boetticher deploy --plan sha256:PLAN_DIGEST --site ./my-boetticher
```

Configuration changes stay in the site until you explicitly deploy them. Use
`--dry-run` when you would like a preview without saving anything.

The [modules guide](modules.html) is where the interesting extras live. The [command menu](commands.html) is there whenever a flag escapes your brain.

## If the first run gets a little weird

Start with the final line from the command that stopped, then work the small ladder:

1. `boetticher status --site ./my-boetticher --live`
2. `boetticher doctor --site ./my-boetticher --live`
3. `boetticher plan --site ./my-boetticher --live --json`
4. Fix the one thing it calls out, refresh the plan, then deploy with its digest.

For a changed Proxmox HOME address, use the address you already know:

```text
boetticher bootstrap-endpoint set PROXMOX_HOME_IP --site ./my-boetticher
boetticher preflight --site ./my-boetticher --live
```

No range scans, no panic cleanup, no ritual sacrifice of a VM. The [lab guide](lab.html#recovery-without-drama) covers the calm recovery order for storage, DNS, a missing platform guest, or a lost age identity.
