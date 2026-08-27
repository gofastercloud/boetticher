# Contributing to boetticher

Thanks for helping make boetticher safer and easier to recover.

## Before you start

Read [agents.md](agents.md), [the architecture guide](docs/architecture.md),
[the security model](docs/security-model.md), and [the ownership boundary](docs/platform-ownership.md).
The most important invariant is that boetticher owns the declared platform,
while Proxmox and the operator own arbitrary user workloads.

For changes that affect bootstrap, credentials, routing, firewall policy,
physical NIC assignment, PKI, backup ownership, or recovery, explain the
failure mode being prevented and add a regression test where possible.

## Development loop

```sh
gofmt -w cmd internal
make ci
```

The repository targets the Go version in `go.mod`. Keep OpenTofu provider locks
and generated contracts deterministic. Do not commit secrets, Age private
identities, OpenTofu state, plans, caches, bootstrap credentials, or live
installation state.

## Pull requests

- Keep changes narrow and describe the user-visible contract.
- Include tests and documentation for new behaviour.
- Preserve explicit `PASS`, `HOLD`, `FAIL`, `NOT TESTED`, and `INCONCLUSIVE` states.
- Do not claim live Proxmox, Debian gateway, DNS, network, or recovery acceptance from local tests alone.
- Do not add generic VM/LXC lifecycle management or silently adopt user guests.
- Do not weaken SSH host-key verification or bypass an ownership boundary to make a test pass.
- Use an imperative commit subject and keep commits cohesive.
- Appliance changes must preserve the hosted-builder contract: public
  allow-listed inputs, qualified Go/tool versions, independent content hashes,
  package/SBOM/Trivy evidence, bounded failure diagnostics, streamed artifact
  transfer, and cleanup of VM 190 after a required build.
- Do not add module application installation to Ansible or generic Debian
  template provisioning. The artifact determines software; deploy injects
  site-specific runtime state.
- Modules declare persistent volumes and placement policy; Core owns physical
  disks, PVs, VGs, filesystems, and destructive storage operations.
- Logging is mandatory and inherited from the common appliance base. DNS is
  one mandatory module with typed Blocky/AdGuard provider selection.
- Keep current-architecture prose direct in docs, help, and comments. Use
  release or migration material for historical wording. A T580 or other live
  hardware journey remains `NOT TESTED` until it is actually run.

## Reporting security issues

Please do not open a public issue containing credentials, private keys,
reproducible exploit details, or sensitive installation data. Follow
[SECURITY.md](SECURITY.md) instead.
