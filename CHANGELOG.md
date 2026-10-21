# Changelog

This is the short, human-readable history of the project: the things likely to
matter when you run or contribute to a lab. It is not a tutorial; the current
guide lives at [lab.davebarton.cc](https://lab.davebarton.cc/).

## Unreleased

The supported workflow is now Controller → one Proxmox Host → capability
Modules: `boetticher controller bootstrap`, `boetticher host
enroll|apply|status`, and `boetticher module <capability> <action>`. The
earlier site directory, signed release bundle, live plan digest, and `deploy`
transaction are retired (see [Start here](docs/start.md)). The Controller is
installed from a locally built payload with `install.sh --from-dir`.

Current capabilities are firewall, DNS, DHCP, and AirVPN egress on one OpenWrt
appliance; a Tailnet subnet router; the integrated observability runtime with
its monitoring, logging, and status-page facets; and the media application.
Existing user guests can be registered as operator-managed systems without
being adopted.

Recent changes:

- Add `host upgrade` (simulated preview, then a noninteractive Proxmox
  full-upgrade in a transient unit) and `host reboot --with-guests`, which
  relies on Proxmox's native guest shutdown and onboot ordering.
- Add the manual `ST-LAB` speedtest to the StreamDeck NETWORK view, run from a
  temporary SERVERS namespace through the firewall's ordinary egress. `ST-VPN`
  stays deferred.
- Bound observability, logging, monitoring, and status-page `status` within one
  30-second read budget, and report a spent budget as undetermined rather than
  unhealthy.
- Reopen the Blinkt with backoff after a transient device failure instead of
  latching it off until the status daemon restarts.
- Let `controller bootstrap` move the Go links off an earlier Boetticher-owned
  toolchain, so an existing Go 1.26.6 Controller installs Go 1.26.10 cleanly.
- Move the Controller toolchain to Go 1.26.10 and update vulnerable Go
  dependencies in the CLI and Caddy modules.
- Refresh the guide: one canonical home for Controller peripherals, a VPN
  client section, the lab snapshot portal, `--home-recovery` in DNS/DHCP help,
  and clearly labelled historical records.

## 0.1.0 — planned, superseded

This label was planned as the first supported release and was never
published. Earlier prototype through 0.5.x labels were internal development
milestones. The items below record what was planned; those marked *retired*
are no longer part of the project.

- *Retired:* build the fixed firewall, DNS/NTP, and monitoring foundation from
  an authenticated signed release bundle.
- *Retired:* keep desired-state changes separate from an exact live plan and a
  bounded deployment transaction. Capability `plan`/`apply` replaced both.
- *Retired from the supported workflow:* endpoint-owned Smallstep certificate
  issuance. Observability uses public DNS-01 certificates and system trust.
- Offer the unified observability runtime, nested Monitoring operations,
  Tailnet routing, firewall-integrated AirVPN, and media capabilities without
  adopting user workloads. These continue as Modules. Operator-managed
  OctoPrint remains a registered user system, not a product-owned module.
- *Retired:* the external Companion Pi. StreamDeck and Blinkt are owned by the
  Controller's status daemon.

The planned `0.1.0` platform label, independent `1.0.0` module appliance
versions, and the `boetticher/v3` schema 3 site API belonged to the retired
bundle design and no longer apply.

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
- Add the historical optional AirVPN transit path for explicit module egress
  (the current supported path is the integrated firewall VPN capability).
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
- Offer monitoring, firewall, logging, DNS, Gatus, Bifrost, and AIOps,
  and Tailnet Router as first-party capabilities with clear defaults. This
  internal milestone predates the unified observability runtime and nested
  Monitoring operation described above.
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
- Added the generated portal, central logging, the former Pulse monitoring
  integration, client
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
