# Changelog

All notable boetticher changes are recorded here. This is a playful pre-alpha
project, so releases can make clean breaks while the design is settling.

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
