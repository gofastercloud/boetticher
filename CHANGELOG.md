# Changelog

This is the short, human-readable history of the project: the things likely to
matter when you run or contribute to a lab. It is not a tutorial; the current
guide lives at [gofastercloud.github.io/boetticher](https://gofastercloud.github.io/boetticher/).

## 0.1.0 — Unreleased

This is the first supported Boetticher release. Earlier prototype through 0.5.x
labels were internal development milestones and were never published as
supported GitHub Releases.

- Build the fixed firewall, DNS/NTP, and monitoring foundation from an
  authenticated signed release bundle.
- Keep desired-state changes separate from the exact live plan and bounded
  deployment transaction that applies them.
- Use endpoint-owned Smallstep certificate issuance while retaining deliberate
  mTLS identities for browser, logging, and bounded service integrations.
- Offer bounded first-party modules for logging, Gatus, Bifrost, AIOps,
  printing, Tailnet routing, AirVPN, and Arr without adopting user workloads.
- Add the external Companion after core setup through a MAC-bound SERVERS
  reservation and restricted Proxmox bastion route.

The platform and base appliance are versioned `0.1.0`. Module appliances retain
their independent `1.0.0` versions and remain bound to exact signed content
digests. The site API remains `boetticher/v3`, schema 3; this release renumber
does not reset or weaken those compatibility identities.

## Pre-release development history

The following labels are retained as engineering history, not supported public
release versions.

### Internal milestone 0.5.0 — 2026-09-03

- Make live deployment consume an authenticated release bundle and an
  immutable plan digest, while keeping site edits and module changes separate
  from deployment.
- Move StreamDeck from the Proxmox module list to the external companion Pi;
  existing 0.4 installations have an explicit migration path for the old
  `lab-streamdeck-01` guest.
- Replace the sprawling guide collection with a small GitHub Pages site, a
  short README, and a generated command menu.
- Add the optional AirVPN transit module for explicit module egress.
- Keep the AI-router client contract while replacing its heavy runtime with
  the in-tree Bifrost implementation for AIOps.
- Run the companion StreamDeck capability in Go with `matthewpi/streamdeck`.

### Internal milestone 0.4.0 — 2026-08-29

#### Highlights

- Make the normal loop `init` → `deploy` → `status`, with separate bootstrap
  and recovery tools for the rare bigger jobs.
- Use Blocky for client-facing recursive and filtering DNS, PowerDNS for
  private authoritative names, and Chrony for NTP.
- Add atomic `update` and a friendly `status` view.
- Bundle the controller's SOPS and age implementations so encrypted secrets
  stay out of ordinary configuration and command output.
- Offer monitoring, firewall, logging, DNS, Gatus, Bifrost, AIOps, printer,
  and Tailnet Router as first-party capabilities with clear defaults.
- Improve host identity checks, appliance replacement, persistent storage, and
  the guarded physical-network workflow.

#### Compatibility notes

- 0.4 uses the `boetticher/v3` site format and fixed 0.4 network layout.
  Recreate older site settings with `boetticher init`.
- Pinned appliance images select application software; Ansible applies the
  site-specific configuration.
- Run `status --live` and the appropriate service checks after a deployment;
  a rendered configuration alone cannot tell you that a wire, host, or browser
  path is working.

### Internal 0.3.x development series

- Established first-party modules, fixed guest names, dedicated ranges for
  platform and user guests, appliance images, persistent data, and `deploy` as
  the platform-changing command.
- Added the managed Debian gateway, VLAN-aware internal networking,
  external-firewall mode, firewall/DHCP inspection, and dedicated storage.
- Added the generated portal, central logging, Pulse monitoring, client
  certificates, USB bindings, recovery material, and module configuration.
- Strengthened Proxmox 9.2 image import, retry, replacement, SSH, and hosted
  builder paths.

### Internal milestone 0.2.0

- Introduced the managed Debian gateway, role-oriented network zones,
  external-firewall handoff, read-only firewall/DHCP commands, and generated
  gateway configuration.
- Replaced the earlier firewall-appliance integration with the current Debian
  gateway design.

### Prototype foundation

The early prototype established the fixed network layout, encrypted site
settings, platform boundary, generated portal, SSH bastion, DNS, storage
profiles, recovery material, and an earlier Zabbix integration that is no
longer part of the project.
