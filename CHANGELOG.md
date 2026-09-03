# Changelog

This is the short, human-readable history of the project: the things likely to
matter when you run or contribute to a lab. It is not a tutorial; the current
guide lives at [gofastercloud.github.io/boetticher](https://gofastercloud.github.io/boetticher/).

## 0.5.0 — 2026-09-03

- Replace the sprawling guide collection with a small GitHub Pages site, a
  short README, and a generated command menu.
- Add the optional AirVPN transit module for explicit module egress.
- Keep the AI-router client contract while replacing its heavy runtime with
  the in-tree Bifrost implementation for AIOps.
- Run the companion StreamDeck capability in Go with `matthewpi/streamdeck`.

## 0.4.0 — 2026-08-29

### Highlights

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

### Compatibility notes

- 0.4 uses the `boetticher/v3` site format and fixed 0.4 network layout.
  Recreate older site settings with `boetticher init`.
- Pinned appliance images select application software; Ansible applies the
  site-specific configuration.
- Run `status --live` and the appropriate service checks after a deployment;
  a rendered configuration alone cannot tell you that a wire, host, or browser
  path is working.

## 0.3.x development series

- Established first-party modules, fixed guest names, dedicated ranges for
  platform and user guests, appliance images, persistent data, and `deploy` as
  the platform-changing command.
- Added the managed Debian gateway, VLAN-aware internal networking,
  external-firewall mode, firewall/DHCP inspection, and dedicated storage.
- Added the generated portal, central logging, Pulse monitoring, client
  certificates, USB bindings, recovery material, and module configuration.
- Strengthened Proxmox 9.2 image import, retry, replacement, SSH, and hosted
  builder paths.

## 0.2.0 — Unreleased

- Introduced the managed Debian gateway, role-oriented network zones,
  external-firewall handoff, read-only firewall/DHCP commands, and generated
  gateway configuration.
- Replaced the earlier firewall-appliance integration with the current Debian
  gateway design.

## 0.1.0 — Pre-alpha history

The early prototype established the fixed network layout, encrypted site
settings, platform boundary, generated portal, SSH bastion, DNS, storage
profiles, recovery material, and an earlier Zabbix integration that is no
longer part of the project.
