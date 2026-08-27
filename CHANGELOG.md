# Changelog

All notable boetticher changes are recorded here. This is a playful pre-alpha
project, so releases can make clean breaks while the design is settling.

## [0.3.23] - 2026-08-27

### Fixed

- Upload deterministic cloud-init snippets through the authenticated host SSH
  path because PVE 9.2's storage upload API excludes snippets content.

## [0.3.22] - 2026-08-27

### Fixed

- Retry a partial bootstrap by revalidating an existing unchecksummed PVE
  import entry through the pinned download task.

## [0.3.21] - 2026-08-27

### Fixed

- Accept the PVE 9.2 import entry after its successful checksum-verified
  download task even though import listings omit checksum fields.

## [0.3.20] - 2026-08-27

### Fixed

- Download the pinned qcow2 builder input as PVE `import` content rather than
  `iso` content, which rejects non-ISO filenames on PVE 9.2.

## [0.3.19] - 2026-08-27

### Fixed

- Trim the trailing newline in PVE 9.2's absent guest-config response before
  classifying the reserved QEMU/LXC identity as not found.

## [0.3.18] - 2026-08-27

### Fixed

- Absent reserved QEMU/LXC guest configurations returned as HTTP 500 by PVE
  9.2 are now treated as not found during ownership inspection.

## [0.3.17] - 2026-08-27

### Fixed

- Proxmox storage reconciliation now uses the `/storage` API present in PVE
  9.2.

## [0.3.16] - 2026-08-27

### Fixed

- Include the PVE SDN audit/use permissions required to observe local Linux
  bridges through the scoped API.

## [0.3.15] - 2026-08-27

### Fixed

- Apply PVE pending network configuration through the supported reload API
  before configuring the management VLAN.

## [0.3.14] - 2026-08-27

### Fixed

- Proxmox network API requests now use the PVE 9.2 underscore field names.

## [0.3.13] - 2026-08-27

### Fixed

- Virtual-only bridge creation no longer sends the invalid `bridge-ports none`
  value rejected by PVE 9.2.

## [0.3.12] - 2026-08-27

### Fixed

- Privilege-separated Proxmox tokens now receive the bounded role through a
  token ACL rather than a user ACL.

## [0.3.11] - 2026-08-27

### Fixed

- Bootstrap reuses an existing encrypted Proxmox credential record after a
  later-stage failure instead of creating a replacement token.

## [0.3.10] - 2026-08-27

### Fixed

- Include the observed `Sys.Modify` permission required to create the
  declared Proxmox virtual bridge.

## [0.3.9] - 2026-08-27

### Fixed

- Document the Proxmox CA trust option across the live installation workflow.

## [0.3.8] - 2026-08-27

### Fixed

- Bootstrap verifies Proxmox API TLS before creating credentials and documents
  the required CA file for self-signed PVE hosts.

## [0.3.7] - 2026-08-27

### Fixed

- Existing Proxmox role validation now accepts the comma-separated privilege
  representation returned by PVE 9.2.

## [0.3.6] - 2026-08-27

### Fixed

- Scoped Proxmox ACL assignment now uses the update endpoint required by PVE
  9.2.

## [0.3.5] - 2026-08-27

### Fixed

- Scoped Proxmox role privileges now use only privilege names supported by PVE
  9.2.

## [0.3.4] - 2026-08-27

### Fixed

- Scoped Proxmox role creation now uses the collection endpoint required by
  PVE 9.2.

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
