# boetticher agent guide

This file is a short orientation for contributors and coding agents. The
repository’s user-facing contracts live in `README.md` and `docs/`; this file
states the engineering guardrails that keep those contracts intact.

## Design

boetticher is an opinionated v0.3 Proxmox distribution, not a generic homelab
framework. The canonical model is deterministic for a fixed platform version,
site configuration, enabled official modules, and relevant secret metadata. Core
composes first-party module declarations and its model revision drives
OpenTofu, Ansible, gateway policy, Zabbix, SSH, portal, inventory, and
verification projections.

boetticher owns only declared platform resources: Proxmox, the managed gateway, the
dual DNS/NTP guests, monitoring, portal, owned bridges/VLAN policy, PKI,
backups, and evidence. Proxmox owns user workloads. Unknown guests are
informational, never drift, and never targets for deletion or import.

## Architecture invariants

- The managed Debian gateway owns routing, NAT, nftables, Kea DHCP, and the inter-zone boundary. External mode publishes a contract only.
- `vmbr0` is the HOME/upstream bridge; `vmbr1` is the internal VLAN-aware bridge.
- V1 is IPv4-only with VLANs 10 TRUSTED, 20 SERVERS, 50 SANDBOX, and 99 MGMT.
- Proxmox is the normal bootstrap/recovery SSH bastion. The managed gateway is reached through that path.
- Physical NIC identity uses observed hardware evidence; interface enumeration order is never architecture.
- Secrets are SOPS-encrypted. The Age private identity, OpenTofu state, plans, caches, and temporary credentials stay outside Git.
- The portal is passive generated static documentation. Zabbix owns live observability.
- Dynamic DNS is lease publication, not workload ownership.
- DNS/NTP is mandatory; monitoring and the managed firewall are default-on.
- Modules are compiled into the release and emit declarations only. Core owns
  privileged mutation, fixed resource identities, appliance artifacts, runtime
  credentials, and replacement/persistence policy.
- Official LXC appliances use the pinned Debian 13 boetticher base. Services run
  non-root where practical, and systemd credentials are the standard secret
  delivery path. PowerDNS backend persistence is an explicit third-party
  exception.
- `boetticher deploy` is the only public platform-application command. Do not
  add a public converge/provision alias.

## Coding standards

- Prefer small, explicit Go functions and standard-library solutions.
- Use deterministic ordering and canonical serialization for model-derived output.
- Make safety checks fail closed. Ambiguity is `HOLD`, not an automatic guess.
- Keep ownership and trust transitions visible in names, output, and tests.
- Use atomic writes for generated files and restrictive permissions for sensitive material.
- Never log, print, accept in arguments, or persist plaintext credentials.
- Do not add a generic Proxmox management abstraction or an incomplete remote-access provider.

## Testing

Run `make ci` before handoff. It covers Go formatting, tests, vet, build,
OpenTofu formatting/validation, Ansible syntax, and whitespace. Add focused
regression tests for ownership boundaries, negative security paths, deterministic
revisions, secret handling, and NIC/bootstrap safety.

Local tests prove source behaviour only. They do not prove a live Proxmox or
Debian gateway installation, authenticated network journey, physical VLAN isolation,
dynamic-DNS replication, or disaster recovery. Preserve `HOLD`, `NOT TESTED`,
and `INCONCLUSIVE` when those gates have not been exercised.

## Documentation and delivery

Update the nearest canonical guide when behaviour changes. Keep the root README
short and task-oriented; deeper runbooks belong under `docs/` and are rendered
by the portal. Inspect the complete staged diff before committing. Use small,
cohesive commits with imperative subjects and do not include unrelated work.
