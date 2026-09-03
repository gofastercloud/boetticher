# Boetticher agent guide

This is the concise contributor contract. Product and qualification detail
belongs in `README.md` and `docs/`; these rules protect the small product from
unsafe or generic control-plane changes.

## Product

- Boetticher is an opinionated Proxmox homelab appliance, not a generic
  orchestrator. Keep normal operation small: `init`, `enroll`, `plan`,
  `deploy`, `status --details`, `module configure`, and `update`.
- Prefer fixed, safe defaults, derivation, and deletion over optionality.
  Keep recovery, physical-network, destructive, and debug paths advanced and
  explicitly guarded.
- Modules are bounded first-party capabilities compiled into the release, not
  plugins, arbitrary workloads, generic ingress, or policy DSLs. Proxmox owns
  user workloads; Boetticher never adopts, imports, or deletes unknown guests.
- Keep the external Pi/StreamDeck companion outside the in-cluster module
  model.

## Architecture and authority

- `internal/model` is the canonical typed v3 contract. Desired configuration
  is authoritative; generated files, observations, and evidence are derived
  projections, never competing authorities.
- Preserve deterministic revisions, fixed VMIDs and addresses, ownership
  ranges, and the HOME `vmbr0` / VLAN-aware `vmbr1` topology with VLANs 5, 10,
  20, 30, 40, and 99.
- Core owns privileged mutation, platform secrets, fixed resource identities,
  appliance artifacts, persistent storage, and replacement policy. Modules
  declare bounded needs and placement only.
- The managed Debian gateway owns routing, NAT, nftables, Kea DHCP/DDNS, and
  the inter-zone boundary. External mode publishes a contract only.
- DNS is mandatory and has one built-in client-facing implementation: Blocky.
  PowerDNS remains authoritative DNS and Chrony remains NTP. Do not add a DNS
  provider selector or generic DNS lifecycle path.
- Appliance artifacts select application software. Ansible performs bounded
  site configuration and verification; it does not replace artifact-selected
  software. `make image-check` validates definitions; `make images` builds.

## Security and lifecycle

- Fail closed on trust, ownership, destructive, ambiguous, malformed, and
  incomplete states. Preserve rich evidence and failure semantics internally.
  Human-facing asserted checks and operations are binary: `PASS` or `FAIL`; do
  not expose `HOLD`, `NOT TESTED`, `INCONCLUSIVE`, `PARTIAL`, `UNKNOWN`, or
  equivalent evidence states as operator results.
- Preserve strict SSH host identity and authenticated bootstrap enrollment.
  Preserve SOPS/Age ownership; secrets never enter argv, logs, JSON, generated
  output, generated public docs, or plaintext temporary files.
- Use atomic writes and path/symlink containment for desired state, generated
  state, archives, and sensitive files. Prove exact Boetticher ownership before
  destructive Proxmox or storage operations.
- `deploy` is the sole normal live-application command. `update` changes
  desired state only. `plan --live` and `status --details` are read-only.
- Temporary privilege requires bounded lifetime, cancellation, and cleanup.
  Cleanup failure is blocking evidence. Live claims require live evidence;
  source tests and generated configuration do not prove deployment, journey,
  or qualification.

## Engineering and delivery

- Prefer concrete, idiomatic Go and small consumer-owned interfaces. Avoid
  generic managers, providers, plugin frameworks, and stringly typed state
  without a concrete current need. Propagate contexts through I/O and process
  boundaries and execute direct argv.
- Fix defects at the narrowest existing ownership boundary. Do not introduce a
  generalized abstraction solely to solve one qualification finding; generalize
  only when multiple concrete current consumers require it.
- Add focused regression tests for behavior or security fixes. Use strict fakes
  at external boundaries and preserve negative and lifecycle coverage.
- Run `make ci` before handoff. Report local, remote, deployed, journey, and
  product evidence separately.
- Keep documentation focused on operator outcomes; keep detailed evidence and
  recovery material in advanced docs. Do not document commands or options the
  binary does not support.
- Keep diffs narrow, inspect the complete staged diff, preserve unrelated
  changes, use feature branches, and never commit directly to `main`.
