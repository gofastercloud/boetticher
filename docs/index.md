---
layout: default
title: Boetticher
section: home
description: Turn a clean Proxmox host into a useful, friendly, properly wired homelab.
---

<section class="hero">
  <div>
    <p class="eyebrow">Automated homelab builder</p>
    <h1>Turn a clean Proxmox host into a very good little lab.</h1>
    <p class="lede">Boetticher gives a clean Proxmox Host one small, repeatable lifecycle from a local Controller.</p>
    <div class="actions">
      <a class="button" href="start.html">Start a fresh lab →</a>
      <a class="button button--quiet" href="https://github.com/gofastercloud/boetticher">Browse the source ↗</a>
    </div>
  </div>
  <figure class="hero__art">
    <img src="images/workbench-hero.webp" alt="Illustrated homelab workbench with a compact server, switch, and control panel">
  </figure>
</section>

## The bits nobody should have to rebuild every weekend

<section class="card-grid">
  <article class="card">
    <h3>A dependable backbone</h3>
    <p>A fixed six-zone network, a Debian gateway when you want one, single-host DNS, DHCP, time, monitoring, and optional capabilities.</p>
  </article>
  <article class="card">
    <h3>A small daily loop</h3>
    <p>Bootstrap the Controller, enroll the Host, apply its baseline, storage, and virtual network, then inspect Host status.</p>
  </article>
  <article class="card">
    <h3>Your workloads stay yours</h3>
    <p>Boetticher builds its own platform guests. Your VMs and Linux Containers (LXCs) remain firmly in your Proxmox lane.</p>
  </article>
  <article class="card card--feature">
    <div>
      <h3>A little chemistry-show wink, not a costume party</h3>
      <p>The name is a nod to breaking out the good gear. The aim is wonderfully ordinary: a homelab that feels considered, useful, and fun to come back to.</p>
    </div>
    <img src="images/boetticher-cover.jpg" alt="Boetticher illustrated project mark">
  </article>
</section>

## Pick the thing in front of you

| When you want to… | Head here |
| --- | --- |
| Build your first lab or learn the everyday rhythm | [Start here](start.html) |
| See how the zones, guests, storage, access, and recovery fit together | [The lab](lab.html) |
| Add a printer, dashboard, AI helper, or AirVPN exit | [Modules](modules.html) |
| Prepare the Controller | [Controller](controller.html) |
| Look up a flag or browse the CLI menu | [Commands](commands.html) |

<aside class="callout">
  <p><strong>Good fit:</strong> a fresh, supported Proxmox VE host on amd64 hardware and a desire for a home lab with less plumbing homework. One Ethernet port is enough to begin; a second port and a VLAN-aware switch unlock a physical trunk or an external firewall later.</p>
</aside>

<aside class="callout">
  <p><strong>The Host boundary:</strong> Host apply owns the Proxmox OS baseline, dedicated storage, and virtual-only <code>vmbr1</code> shape. Modules and physical LAB networking are later work.</p>
</aside>

## A quick glossary

<dl class="glossary">
  <dt>Proxmox VE</dt>
  <dd>The virtualisation host for your VMs and Linux Containers. Its <a href="https://pve.proxmox.com/pve-docs/">documentation</a> is superb.</dd>
  <dt>VLAN</dt>
  <dd>A virtual local-area network: one physical cable can carry several separate networks. This <a href="https://www.cloudflare.com/learning/network-layer/what-is-a-vlan/">VLAN explainer</a> makes it pleasantly concrete.</dd>
  <dt>Controller</dt>
  <dd>The machine that runs Boetticher, keeps the persistent administrative identity, and owns attached Controller peripherals. The current reference implementation is a Raspberry Pi.</dd>
</dl>

## Built by a lot of clever people

Boetticher is the small connector between a pile of fantastic open-source work. Huge thanks to the maintainers of [Proxmox VE](https://www.proxmox.com/), [Debian](https://www.debian.org/), [Ansible](https://www.ansible.com/), [Pulse](https://github.com/rcourtman/Pulse), [Blocky](https://github.com/0xERR0R/blocky), [PowerDNS](https://www.powerdns.com/), [Chrony](https://chrony-project.org/), [WireGuard](https://www.wireguard.com/), and every project in the [third-party notices](https://github.com/gofastercloud/boetticher/blob/main/THIRD_PARTY_NOTICES.md). They did the hard work; this project is delighted to stand on it.
