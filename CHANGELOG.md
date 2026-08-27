# Changelog

All notable boetticher changes are recorded here. This is a playful pre-alpha
project, so releases can make clean breaks while the design is settling.

## [0.3.33] - 2026-08-27

### Fixed

- Encode the managed firewall's QEMU cloud-init SSH key in the format required
  by the Proxmox 9.2 API.
- Bound QEMU persistent-disk serials to Proxmox's 36-character limit and migrate
  the deterministic legacy serial on retry.
- Match Proxmox's expanded persistent-disk volume identifiers when validating
  or resuming an owned QEMU guest.
- Upload qualified QEMU appliance images through Proxmox's supported `import`
  content class before importing them into the selected VM storage.
- Send streamed Proxmox artifact uploads with a computed `Content-Length`,
  which the pveproxy upload endpoint requires.
- Emit upload checksum metadata in the field order expected by pveproxy.
- Revalidate a checksum-less partial QEMU import by re-uploading the qualified
  local bytes before retrying deployment.
- Use the existing authenticated Proxmox SSH path for cloud-init snippets;
  PVE 9.2 does not accept `snippets` through the storage upload API.
- Select the local operator private key for deploy-time Proxmox and appliance
  SSH when the site does not override `ssh_identity_file`.
- Include the managed `labadmin` account in the Proxmox SSH allow-list during
  bootstrap so routine bastion access does not depend on root.
- Include the managed `lab-jump` bastion account in the same allow-list so
  gateway readiness can use the documented Proxmox jump path.
- Set the managed bastion authorized-key file ownership so privilege-separated
  sshd can read it on the Proxmox host.
- Reset appliance sudoers ownership during image construction so sudo can run
  its no-password bootstrap checks after deployment.
- Require explicit confirmation for an owned appliance rootfs replacement and
  resume it while retaining declared persistent volumes.
- Refresh firewall cloud-init snippets and persist the artifact identity when
  an owned rootfs replacement is resumed, so bounded persistent-disk serials
  are mounted on the replacement boot.
- Address firewall persistent volumes through Debian's stable PVE SCSI-slot
  links; the QEMU serial remains the Proxmox ownership identity but does not
  produce a guest `/dev/disk/by-id` link on the qualified image.
- Refresh the managed gateway cloud-init snippets when an existing owned guest
  is resumed, keeping its next supported first-boot/recovery path current.
- Resume an owned running gateway without issuing a duplicate Proxmox start
  request after a prior deployment attempt.
- Discover the hosted builder address through the QEMU guest agent after
  confirming the guest reaches userspace.
- Start the hosted builder guest agent before the remaining qualification
  downloads.
- Decode the Proxmox QEMU guest-agent interface response from its `result`
  object so hosted-builder address readiness matches the live API contract.
- Use Debian 13's `trixie` suite name when mmdebstrap consumes the pinned
  snapshot; the numeric `13` suite returned 404 during hosted construction.
- Add bounded stage markers to hosted-builder output so a failed appliance
  construction identifies the exact build phase.
- Label the existing appliance smoke checks in hosted-builder diagnostics so
  failed base-contract checks identify the exact assertion.
- Label the smoke preamble assertions so artifact identity and baked-identity
  failures remain diagnosable in the hosted-builder log.
- Accept compact JSON whitespace in the artifact identity smoke check; the
  generated Go JSON is valid without a space after the field separator.
- Invoke the Debian 13 journal-upload binary by its installed path during
  base-image smoke checks; the systemd service name is not a PATH executable.
- Include the logging package in the embedded public builder source; Blocky
  qualification imports it through the composed module declarations.
- Include the same logging package in the transferred public-input allow-list
  so embedded and source-checkout builder archives remain equivalent.
- Label DNS appliance smoke assertions so a hosted-builder failure after base
  packaging identifies the specific provider or runtime check.
- Invoke Blocky’s `version` subcommand in the DNS smoke check; Blocky 0.34
  does not expose the version through a `--version` flag.
- Invoke the Debian 13 journal-remote binary by its installed path in the
  logging smoke check; its systemd service name is not a PATH executable.
- Quote the firewall package-manifest format through the guest shell so
  `dpkg-query` receives its `${binary:Package}` and `${Version}` placeholders.
- Disable the firewall image's network wait-online unit without `--now`, which
  is rejected by offline systemd customization.
- Accept compact JSON whitespace in the firewall image definition-identity
  smoke check as well as the LXC appliance check.
- Report package, CVE, and fixed-version details when Trivy rejects an
  artifact for fixable CRITICAL findings, preserving the next investigation
  step in hosted-builder diagnostics.
- Advance the pinned Debian snapshot to include the security revisions
  required by the first live Trivy qualification; the prior snapshot supplied
  vulnerable GnuTLS and OpenSSL packages.
- Preserve secret-scan target, rule, category, and line diagnostics without
  emitting the detected secret value when artifact qualification fails.
- Include the matching pinned Debian security snapshot in appliance and
  hosted-builder package sources so security-only fixes are available without
  making package resolution unpinned.
- Remove Debian's generated snakeoil private key from appliance images before
  Trivy qualification; endpoint keys remain deployment-time identity material.
- Upgrade pre-existing packages in the imported firewall cloud image before
  installing the firewall contract, so pinned Debian security fixes are not
  skipped for already-installed packages.

## [0.3.32] - 2026-08-27

### Fixed

- Explicitly attach the hosted builder disk through the qualified
  `virtio-scsi-single` controller.

## [0.3.31] - 2026-08-27

### Fixed

- Keep the temporary hosted builder on the direct HOME bridge so Proxmox's
  disabled guest-firewall path cannot block its DHCP bootstrap.

## [0.3.30] - 2026-08-27

### Fixed

- Match the observed Debian virtio builder interface name `ens18` for DHCP
  while preserving the exact builder MAC match.

## [0.3.29] - 2026-08-27

### Fixed

- Boot the temporary builder from its imported `scsi0` disk before the
  cloud-init drive and network PXE path.

## [0.3.28] - 2026-08-27

### Fixed

- Discover the temporary DHCP builder through its exact HOME neighbor entry
  before waiting for cloud-init to install the guest agent.

## [0.3.27] - 2026-08-27

### Fixed

- Install and start the builder guest agent in the early pinned bootstrap
  stage so address readiness does not wait for the later build command stage.

## [0.3.26] - 2026-08-27

### Fixed

- Import QEMU builder and gateway disks through the supported PVE 9.2
  `import-from` configuration path.

## [0.3.25] - 2026-08-27

### Fixed

- Avoid the PVE 9.2-invalid `sshkeys` create parameter when the builder's
  custom user-data already carries the operator key.

## [0.3.24] - 2026-08-27

### Fixed

- Preserve structured PVE parameter errors in API failures so live bootstrap
  diagnostics identify the rejected field.

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
