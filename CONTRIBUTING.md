# Contributing to Boetticher

Thanks for helping make Boetticher useful, understandable, and safe to
recover. Start with the [project guide](AGENTS.md), [architecture](docs/architecture.md),
[security model](docs/security-model.md), and [ownership boundary](docs/platform-ownership.md).

## The shape of the project

Boetticher is an opinionated homelab appliance, not a generic VM manager or
infrastructure framework. Prefer a small fixed contract, a concrete Go
implementation, and deletion over a new abstraction. Modules are bounded
first-party capabilities; Core owns platform mutation and user workloads stay
outside the model.

Keep one authoritative representation of desired configuration. Generated
files, observations, and test or qualification records are projections. Do
not weaken ownership checks, SSH host verification, SOPS/Age boundaries,
destructive confirmations, or the distinction between local checks and live
acceptance.

## Development loop

```sh
gofmt -w cmd internal
make ci
```

Use the Go version declared in `go.mod`. Keep generated contracts
deterministic and regenerate command or schema references from their source.
Do not commit secrets, Age private identities, caches, bootstrap credentials,
or live installation state.

For a behavior or security fix, add a focused regression test. For changes to
bootstrap, credentials, routing, firewall policy, physical NIC assignment,
PKI, backup ownership, or recovery, explain the failure mode being prevented.

## Pull requests

- Keep changes narrow and describe the user-visible contract.
- Include tests and documentation for new behavior.
- Keep `PASS`, `HOLD`, `FAIL`, `NOT TESTED`, and `INCONCLUSIVE` meaningful; do
  not claim live Proxmox, DNS, network, or recovery acceptance from local tests.
- Do not add generic VM/LXC lifecycle management or adopt user guests.
- Do not weaken host-key verification or bypass ownership checks to make a
  test pass.
- Keep application software in deterministic appliance artifacts. Ansible
  applies bounded site configuration and verification; it does not replace
  artifact-selected software.
- Modules declare bounded placement and persistent needs; Core owns physical
  storage and destructive lifecycle operations.

## Reporting security issues

Please do not open a public issue containing credentials, private keys,
exploit details, or sensitive installation data. Follow [SECURITY.md](SECURITY.md).
