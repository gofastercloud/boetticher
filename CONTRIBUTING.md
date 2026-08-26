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

## Reporting security issues

Please do not open a public issue containing credentials, private keys,
reproducible exploit details, or sensitive installation data. Follow
[SECURITY.md](SECURITY.md) instead.
