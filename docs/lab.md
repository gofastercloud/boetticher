---
layout: default
title: The lab
section: lab
description: The Boetticher network, platform guests, access routes, storage, recovery, and the bigger experiments.
---

# Your lab, demystified

Boetticher has opinions on purpose. A fixed shape means less time wondering what an address is for and more time making the services you actually wanted to run.

<section class="split">
  <div>
    <h2>The network at a glance</h2>
    <p><code>vmbr0</code> stays on your existing HOME or upstream network. <code>vmbr1</code> is the VLAN-aware internal bridge. In the default setup it has no physical member, so one network port is enough.</p>
    <p>The managed gateway is <code>lab-fw-01</code> at <code>10.10.99.1</code>. It handles routing, DHCP (Dynamic Host Configuration Protocol), network address translation (NAT), dynamic DNS, time for SANDBOX, and the boundaries between zones.</p>
  </div>
  <figure>
    <img class="section-art" src="images/network-lab.webp" alt="Illustrated compact homelab nodes connected by ordered glowing paths and laboratory glassware">
    <figcaption class="art-caption">A much calmer network diagram than the one in your head at 1 a.m.</figcaption>
  </figure>
</section>

| Zone | Network | What it is for |
| --- | --- | --- |
| **VLAN 5 TRANSIT** | `10.10.5.0/24` | Small transit services, including the optional AirVPN exit. |
| **VLAN 10 INFRA** | `10.10.10.0/24` | DNS, monitoring, logs, and the portal. |
| **VLAN 20 SERVERS** | `10.10.20.0/24` | Reserved-address servers and application guests. |
| **VLAN 30 TRUSTED** | `10.10.30.0/24` | Laptops, desktops, and other familiar clients. |
| **VLAN 40 SANDBOX** | `10.10.40.0/24` | Disposable devices and experiments. |
| **VLAN 99 MGMT** | `10.10.99.0/24` | Proxmox and the gateway’s management side. |

## The platform guests

The names are intentionally boring enough to remember at 2 a.m.

| Guest | Address / URL | Job |
| --- | --- | --- |
| `lab-proxmox-01` | `10.10.99.5` · `https://proxmox.lab.home.arpa:8006` | The Proxmox host. |
| `lab-fw-01` | `10.10.99.1` | The managed Debian firewall. |
| `lab-dns-01` | `10.10.10.10` | Primary DNS and Network Time Protocol (NTP). |
| `lab-dns-02` | `10.10.10.11` | Secondary DNS and NTP. |
| `lab-monitor-01` | `10.10.10.20` · `https://monitor.lab.home.arpa` | Pulse Community 6.1.2 monitoring. |
| `lab-portal-01` | `10.10.10.30` · `https://portal.lab.home.arpa` | The generated platform portal. |
| `lab-log-01` | `10.10.10.40` | Central systemd journal. |

The private domain is `lab.home.arpa`. [Blocky](https://0xerr0r.github.io/blocky/) answers client DNS queries, [PowerDNS](https://doc.powerdns.com/authoritative/) owns Boetticher’s private names, and [Chrony](https://chrony-project.org/) keeps clocks in step. The gateway image is pinned as `debian-13-genericcloud-amd64-20260327-2429`, so a new deployment starts from the same known operating-system image every time.

## Built to get out of your way

Boetticher makes the pinned Debian base and the platform appliances it actually needs. The short-lived builder gets approved public build inputs and a separately owned cache of verified downloads; it does not receive your site settings, encrypted secrets, CA keys, or Git write access. Matching images are reused on later deploys, while stale or changed ones are rebuilt from scratch.

The big base and firewall stages go first; independent smaller appliances can be built in a bounded pair. The builder records short build and scan timings for anyone who enjoys a good before-and-after, but the ordinary routine remains delightfully simple: deploy, check the lab, carry on.

## Your workloads have their own lane

Create your own VMs and LXCs in Proxmox. Put their NIC on <code>vmbr1</code>, tag it with the zone you want, and let DHCP do the ordinary network setup. A SERVERS reservation gives you a stable address and friendly private name. You can add your own A and CNAME records with <code>boetticher dns record</code>.

Boetticher reserves these guest-number ranges:

- `100–199` for core platform guests;
- `200–499` for optional Boetticher modules; and
- `500–899` for your VMs and LXCs.

It does not adopt a guest just because the name or address looks familiar. That leaves plenty of room for the inventive, slightly chaotic part of a homelab without turning the platform into a generic VM manager.

## Getting in

Most browser-facing platform services use a client certificate. The friendly shorthand is mTLS: mutual Transport Layer Security, where your browser or device and the service both present certificates. A quick primer is [Cloudflare’s mTLS overview](https://www.cloudflare.com/learning/access-management/what-is-mutual-tls/).

```text
boetticher pki client create dave-laptop --site ./my-boetticher
boetticher pki client export dave-laptop --site ./my-boetticher --output ./dave-laptop.p12
boetticher ssh-config --site ./my-boetticher --output ./boetticher-ssh.conf
```

Import the `.p12` file into your browser or operating system, then visit a service such as `https://monitor.lab.home.arpa`. The generated SSH config knows the platform names and the route through the bastion. The everyday front doors are the Boetticher CLI, Proxmox, and each service’s own web UI; direct console access is the recovery tool when the ordinary route is unavailable.

[Tailscale](https://tailscale.com/) is optional and can make selected lab networks reachable from your tailnet. It is a subnet router, not an Internet exit node. Cloudflare Tunnel and a separate WireGuard gateway are not first-party ingress paths in this release.

## Recovery without drama

Keep your private site repository, the independent age identity that unlocks its encrypted secrets, certificate/recovery material, and any off-host backups in separate safe places. The site describes the lab; temporary runtime files, generated config, and image caches can all be made again.

The default single-disk storage profile is the easiest way to start. With a spare disk, Boetticher can make a separate LVM layout:

| Name | Job |
| --- | --- |
| `vg_boetticher` | The volume group on the chosen disk. |
| `boetticher-thin` | Thin storage for guest images and root filesystems. |
| `boetticher-backups` | Local backup storage. |

If a deployment stops or a service disappears, begin here:

```text
boetticher status --site ./my-boetticher --live
boetticher doctor --site ./my-boetticher --live
```

Then recover the site repository and age identity, restore the Proxmox management path if needed, run `preflight --live`, and deploy to rebuild Boetticher’s own platform pieces. Reattach or restore persistent application data, check the services you care about, then take a fresh off-host backup. Do not delete an unfamiliar VM, LXC, volume, or network device just to make a later run quieter.

If Proxmox itself is fresh or the bootstrap path is lost, use the guarded recovery sequence instead of jumping straight to deploy:

```text
boetticher bootstrap-endpoint set PROXMOX_HOME_IP --site ./my-boetticher
boetticher preflight --site ./my-boetticher --live --record --trunk-interface IFACE
boetticher bootstrap --site ./my-boetticher --recovery-confirmed --proxmox-ca /path/to/pve-root-ca.pem --trunk-interface IFACE
boetticher bundle import ./boetticher-0.5.0.tar.gz --site ./my-boetticher
boetticher plan --site ./my-boetticher --live --json
boetticher deploy --plan sha256:PLAN_DIGEST --site ./my-boetticher
```

Use `--storage-confirmed` as well when the site uses the dedicated-data-disk profile, after checking the stable device identity.

## When you want to go bigger

### Add a physical VLAN trunk

With a suitable second NIC and a VLAN-aware switch, inspect the candidate and attach it explicitly:

```text
boetticher network trunk status --site ./my-boetticher --live
boetticher network trunk attach IFACE --confirm --site ./my-boetticher
```

The trunk carries VLANs 5, 10, 20, 30, 40, and 99. HOME stays on `vmbr0`; do not put it on the internal trunk. Use `network trunk detach` to reverse the choice just as deliberately.

### Run your own firewall

Start with <code>boetticher init --external-firewall</code> when you want your own firewall appliance to be the gateway. Boetticher still produces the lab layout and the settings your appliance needs; your firewall supplies the six VLANs, gateway addresses, DHCP where applicable, DNS and NTP routes, NAT, and the same separation between zones.

### Give the lab a shakedown

```text
boetticher network test --site ./my-boetticher --zones TRUSTED,SANDBOX
boetticher firewall counters --site ./my-boetticher --live
```

`network test` makes tiny temporary LXCs in VMIDs 910–919, checks selected paths, then cleans up its own probes. Use `--capture` only while chasing one route; `--cleanup-only` is there for a probe interrupted mid-test. With enabled ARR and AirVPN, `--airvpn` also proves the declared ARR source has public tunnel egress, cannot reach Proxmox management, and loses public egress while the exact AirVPN LXC is stopped and restored.

StreamDeck is a capability of a Boetticher companion device, not a Proxmox
module. Attach it directly to the companion Pi; the Pi can also provide the
kiosk display and optional Pulse host agent. Generic Proxmox USB export remains
available for actual guest peripherals.
