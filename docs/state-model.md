# State and determinism

The platform has one canonical model: the normalized `site.yml` plus the enabled component declarations and relevant public secret metadata. For a fixed boetticher version, site, enabled modules, and generated secret identities/metadata, the desired-state model and its projections are deterministic.

The model revision is a SHA-256 digest rendered as `sha256:<hex>`. It is included in generated model, inventory, OPNsense, Proxmox, Zabbix, Ansible, SSH, portal, and verification artifacts. Timestamps and live verification evidence are intentionally excluded from the digest.

Installation-specific physical bindings are part of desired state only as stable upstream/trunk identities (permanent MAC and PCI identity, with the current interface name as observed context). Driver, model, speed, carrier, and live bridge/address evidence are generated status data and do not affect the model digest.

## Repository state

The private site repository may contain:

- desired state and module declarations;
- `.sops.yaml` with the public Age recipient;
- encrypted SOPS documents;
- exact platform/version locks;
- non-secret generated model, portal, inventory, and verification evidence.

The repository must not contain the Age private identity. Keep it under the operator-owned restrictive path `~/.config/boetticher/age/identity.txt` or an explicitly selected equivalent.

## Runtime state

OpenTofu state, plans, provider/plugin caches, Ansible caches, bootstrap state, temporary generated credentials, API responses containing secrets, and endpoint private keys live outside Git and are treated as potentially sensitive. The portal consumes only generated non-secret artifacts and status evidence; it has no control-plane credentials.

`boetticher doctor` checks projections as `ABSENT`, `CURRENT`, or `INCONSISTENT` against the current revision. A current projection proves only model consistency, not deployment or authenticated service behavior.
