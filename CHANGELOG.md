# Changelog

All notable boetticher changes are recorded here. This is a playful pre-alpha
project, so releases can make clean breaks while the design is settling.

## [0.3.3] - 2026-08-27

### Fixed

- Preflight now honors an explicitly configured virtual-only network and
  leaves eligible spare NICs unclaimed unless trunk selection is explicit.

## [0.3.2] - 2026-08-27

### Fixed

- Proxmox network discovery now preserves hardware identity from an exact
  Linux `enx<mac>` interface name when the Proxmox response omits `hwaddr`.
  Arbitrary interface names remain ambiguous and fail closed.

## [0.3.0] - Unreleased

This release is an intentional schema break. Sites use `boetticher/v3` and
must be recreated with `boetticher init`.

### Added

- First-party declarative `dns`, `monitoring`, and `firewall` modules with
  mandatory, default-on, and default-off enablement policies.
- Deterministic module composition, capability checks, fixed guest identities,
  declaration ownership, artifact metadata, and appliance replacement-state
  contracts.
- `boetticher deploy` as the sole public platform-application command.
- Module lifecycle and configuration inspection commands, including dry-run
  plans and explicit confirmation for configuration changes.
- A checked-in v3 JSON Schema and Debian 13 appliance build definitions.
- Explicit persistent-state and systemd-credential contracts, including the
  protected PowerDNS backend exception for TSIG material.

Live Proxmox, appliance image construction, credential installation, service
journeys, and physical network qualification remain untested.

## [0.2.0] - Unreleased

This release is intentionally incompatible with older pre-alpha site state.

### Added

- A managed Debian gateway VM, `lab-fw-01`, using nftables, Kea, and ordinary
  role-oriented network interfaces.
- Proxmox-side VLAN tagging for separate WAN, TRUSTED, SERVERS, SANDBOX, and
  MGMT gateway vNICs.
- Explicit external-firewall mode and a generated vendor-neutral contract.
- Read-oriented `firewall` and `dhcp` CLI commands.
- Deterministic gateway policy and external contract projections.

### Changed

- The site schema and platform release are now `boetticher/v2` and `0.2.0`.
- Platform backup convergence refuses to overwrite a conflicting Proxmox job
  with the reserved name unless its boetticher ownership marker is present.
- `firewall status --live` reports observed forwarding, role-oriented
  interfaces, and required managed-gateway services.
- Dedicated storage status and `doctor --live` inspect the expected disk,
  fixed LVM layout, backup mount, Proxmox registrations, and capacity.
- Gateway DHCP, DNS forwarding, NTP, firewall, monitoring, access, recovery,
  and portal documentation describe the current Debian architecture.

### Removed

- The former firewall-appliance runtime integration, credentials, API path,
  generated artifacts, and core documentation.

Live Proxmox, Debian service, physical VLAN, DHCP/DDNS, and external-appliance
journeys remain part of the first real installation work.

## [0.1.0] - Pre-alpha history

The earlier pre-alpha foundation established the fixed network model, encrypted
site state, platform ownership boundary, generated portal, SSH bastion, DNS,
Zabbix, storage profiles, and recovery contracts.
