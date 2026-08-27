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

boetticher owns only its declared platform resources and generated platform
state. Observation or discovery never creates ownership. Proxmox owns user
workloads. Unknown guests are informational, never drift, and never targets
for deletion or import.

## Architecture invariants

- The managed Debian gateway owns routing, NAT, nftables, Kea DHCP, and the inter-zone boundary. External mode publishes a contract only.
- `vmbr0` is the HOME/upstream bridge; `vmbr1` is the internal VLAN-aware bridge.
- V1 is IPv4-only with VLANs 5 TRANSIT, 10 INFRA, 20 SERVERS, 30 TRUSTED,
  40 SANDBOX, and 99 MGMT.
- Proxmox is the normal bootstrap/recovery SSH bastion. The managed gateway is reached through that path.
- Physical NIC identity uses observed hardware evidence; interface enumeration order is never architecture.
- Secrets are SOPS-encrypted. The Age private identity, OpenTofu state, plans, caches, and temporary credentials stay outside Git.
- The portal is passive generated static documentation. Zabbix owns live observability.
- Dynamic DNS is lease publication, not workload ownership.
- DNS/NTP is mandatory; monitoring and the managed firewall are default-on.
- Modules are compiled into the release and emit declarations only. Core owns
  privileged mutation, fixed resource identities, appliance artifacts, runtime
  credentials, and replacement/persistence policy.
- Reserved fixed guest identities, including the temporary builder VMID 190,
  fail closed with `HOLD` for any unowned or wrong-kind occupant; boetticher
  never allocates around a collision or adds ownership tags to prove ownership.
- Bootstrap builds deployable appliances only through the bounded temporary
  Linux builder. `make image-check` validates definitions; `make images`
  produces the real appliance artifacts. Deploy requires the expected
  definition identity, a verified content SHA-256, successful build smoke
  checks, and a completed passing Trivy policy check.
- VM 190 (`lab-builder-01`) is ephemeral Core infrastructure on `vmbr0`, sized
  at 4 vCPUs, 8 GiB RAM, and 32 GiB minimum root storage. Every construction
  attempt that needs a build starts from a fresh proven builder, uses only the
  public allow-listed source bundle, records bounded diagnostics on failure,
  streams artifacts, and destroys the VM plus its disposable host-key database
  and exact cloud-init snippets.
- The builder uses the explicitly qualified Go toolchain. It may record
  tool/version provenance for debugging, but provenance is informational and
  must not block an otherwise valid artifact from deployment. Scoped Proxmox
  privileges must cover only the actual VM, snippet, guest-agent,
  template-upload, and artifact-storage operations; a blanket administrator
  role is not acceptable.
- Official LXC appliances use the pinned Debian 13 boetticher base. Services run
  non-root where practical, and systemd credentials are the standard secret
  delivery path. PowerDNS backend persistence is an explicit third-party
  exception.
- `boetticher deploy` is the only public platform-application command. Do not
  add a public converge/provision alias.
- Central logging is a mandatory platform service. Managed Linux endpoints
  inherit bounded journald and asynchronous mTLS journal upload from the
  common base; modules do not invent transports.
- DNS is one mandatory module with typed `blocky`/`adguard` provider selection.
  Both providers share PowerDNS/Chrony and the common DNS conformance contract.
- Monitoring is Core infrastructure in INFRA at `10.10.10.20`; MGMT is not a
  generic application placement zone.
- Official artifacts have a deterministic definition identity and a verified
  SHA-256 for the concrete bytes being deployed. Build smoke tests and Trivy
  policy must pass. Package manifests, SBOMs, scanner reports, and builder
  metadata are useful diagnostic/release outputs but are not additional
  desired-state authorities. Metadata-only artifacts are not deployable.
- Modules declare persistent volumes and placement preferences. Core alone owns
  physical disks, PVs, VGs, filesystems, and destructive storage lifecycle.
- Appliance artifacts determine module-version-determined application
  software. Ansible may currently perform bounded site-specific runtime
  configuration, service enablement, certificate/config installation, and
  verification, but it must not install or replace the application software
  selected by the appliance artifact.
- `make images` is real Linux artifact construction and `make image-check` is
  static validation only. Hosted-builder qualification is a release gate;
  source tests do not prove a T580 or Proxmox deployment. Until that workflow
  is physically executed, hardware and live service behavior remain
  `NOT TESTED`.

## Coding standards

- Prefer small, explicit Go functions and standard-library solutions.
- Use deterministic ordering and canonical serialization for model-derived output.
- Make safety checks fail closed. Ambiguity is `HOLD`, not an automatic guess.
- Keep ownership and trust transitions visible in names, output, and tests.
- Use atomic writes for generated files and restrictive permissions for sensitive material.
- Never log, print, accept in arguments, or persist plaintext credentials.
- Systemd credentials are the standard runtime secret delivery path; endpoint
  PKI keys remain endpoint-local and PowerDNS protected-backend persistence is
  an explicit, recoverable exception.
- Do not add a generic Proxmox management abstraction or an incomplete remote-access provider.
- When choosing between more offline assurance and a safe real execution test,
  prefer the real execution test once known deterministic blockers are closed.

## Delivery discipline

boetticher is pre-alpha. Prefer obtaining real execution evidence from the
supported deployment workflow over expanding offline abstractions.

Before introducing a new abstraction, metadata type, lifecycle state, policy
layer, generated artifact, or framework, answer:

1. What concrete current failure does this solve?
2. Does it prevent unsafe mutation, secret exposure, or a known first-deployment
   blocker?
3. Can the first live trial proceed safely without it?

If the third answer is yes and the first two answers are no, defer the work.

Additional rules:

- During an explicitly authorized live qualification, minor permission or ACL
  mutations are allowed only when they are the minimum required for the
  observed product path, preserve the security boundary, target an exact
  boetticher-owned object, and are documented with the failure and resulting
  state. This does not authorize credential disclosure, unrelated resources,
  or broad privilege grants.
- Prefer the smallest implementation that enables the next real test.
- Do not make diagnostic, provenance, audit, or reporting metadata a deployment
  prerequisite unless it directly enforces a current safety property.
- Do not create abstractions for hypothetical future consumers. Require at
  least two concrete current uses before generalising.
- Do not add a framework to eliminate a small amount of explicit code.
- Do not expand a task merely because adjacent cleanup is available.
- Once deterministic blockers are closed and CI is green, run the real
  workflow instead of adding another assurance tranche.
- A failed real deployment with useful diagnostics is progress.
- `NOT TESTED` is an acceptable and preferred status for behavior that requires
  real infrastructure.
- Optimize pre-alpha work for testability, recoverability, and clear failure,
  not theoretical completeness.

## Testing

Run `make ci` before handoff. It covers Go formatting, tests, vet, build,
OpenTofu formatting/validation, Ansible syntax, and whitespace. Add focused
regression tests for ownership boundaries, negative security paths, deterministic
revisions, secret handling, and NIC/bootstrap safety.

A source-level test should protect a concrete contract or regression. Do not
add tests whose primary purpose is to justify a newly invented abstraction or
metadata layer.

Local tests prove source behaviour only. They do not prove a live Proxmox or
Debian gateway installation, authenticated network journey, physical VLAN isolation,
dynamic-DNS replication, or disaster recovery. Preserve `HOLD`, `NOT TESTED`,
and `INCONCLUSIVE` when those gates have not been exercised.

## Documentation and delivery

Update the nearest canonical guide when behaviour changes. Keep the root README
short and task-oriented; deeper runbooks belong under `docs/` and are rendered
by the portal. Inspect the complete staged diff before committing. Use small,
cohesive commits with imperative subjects and do not include unrelated work.
