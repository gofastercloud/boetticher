# Changelog

This file records changes that matter to people using or contributing to
Boetticher. It is not a deployment or qualification report.

## Unreleased

- Clarify the 0.4 operator journey, module choices, recovery guidance, and
  third-party attribution before source freeze.

## 0.4.0 — 2026-08-29

### Highlights

- Use the small `init` → `deploy` → `status` workflow for normal operation,
  with guarded bootstrap and recovery paths when needed.
- Make Blocky the sole built-in client-facing recursive/filtering DNS
  implementation; PowerDNS remains authoritative DNS and Chrony remains NTP.
- Add atomic desired-state `update` and a semantic `status` view.
- Bundle the controller's SOPS and age implementations, with encrypted secret
  handling kept outside ordinary configuration and command output.
- Keep monitoring, firewall, logging, DNS, Gatus, LiteLLM, AIOps, printer,
  and Tailnet Router as bounded first-party capabilities with explicit defaults.
- Improve ownership checks, host trust, appliance replacement, persistent
  storage handling, and guarded physical-network transitions.

### Compatibility notes

- 0.4 uses the `boetticher/v3` site contract and the fixed 0.4 network model.
  Older site state should be recreated with `boetticher init`.
- Application software is selected by deterministic appliance artifacts;
  Ansible applies bounded site configuration and verification.
- Local checks and generated files do not by themselves prove a live
  installation, service journey, physical network, or recovery result.

## 0.3.x development series

- Established deterministic first-party modules, fixed guest identities,
  ownership ranges, appliance artifacts, persistent-state contracts, and
  `boetticher deploy` as the sole platform-application command.
- Added managed Debian gateway, VLAN-aware internal networking, explicit
  external-firewall mode, bounded firewall/DHCP inspection, and guarded
  dedicated storage.
- Added the generated portal, central logging, Pulse monitoring, PKI, USB
  bindings, recovery projections, and module configuration planning.
- Hardened Proxmox 9.2 artifact import, retry, replacement, SSH, and hosted
  builder paths.

## 0.2.0 — Unreleased

- Introduced the managed Debian gateway, role-oriented network zones,
  external-firewall contract, read-oriented firewall/DHCP commands, and
  deterministic gateway projections.
- Replaced the earlier firewall-appliance integration with the current Debian
  gateway design.

## 0.1.0 — Pre-alpha history

The early prototype established the fixed network model, encrypted site state,
platform ownership boundary, generated portal, SSH bastion, DNS, storage
profiles, recovery contracts, and an earlier Zabbix integration that is not
part of the current platform.
