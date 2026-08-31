# Normal operations

After the first installation, most work follows this small loop:

```text
change configuration → deploy → status
```

Use [installation](installation.md) for the first host setup. `deploy` is the
normal command that applies the platform; `status` is the first place to look
when something needs attention.

## Everyday commands

```text
boetticher deploy --site ./my-boetticher --dry-run
boetticher deploy --site ./my-boetticher
boetticher status --site ./my-boetticher --live
boetticher doctor --site ./my-boetticher --live
```

Use `boetticher module configure NAME` to change an optional module, then run
`deploy` separately. Use `boetticher logs` for a bounded view of central
logs. The [module guide](modules/architecture.md) explains what each built-in
capability does and what it keeps.

`update` changes compatible desired configuration and projections; it does not
deploy. `upgrade` is an advanced, currently blocked compatibility gate, not a
normal release-update command.

## Backups, recovery, and networking

Read [backup ownership](storage/backup-ownership.md) before relying on the
platform backup job, and keep an independent copy of the site repository,
Age identity, and important data. The [recovery guide](recovery/recovery.md)
is the starting point after a failed appliance, lost DNS, or storage problem.

Managed installations are virtual-only by default. Use the
[physical-trunk guide](networking/physical-trunk.md) only when a real trunk is
required; physical changes are guarded because they can interrupt management.
In external-firewall mode, routing, DHCP, NAT, and the network boundary stay
with the operator's appliance.

## Detailed diagnostics

`status` and `verify` use the same current health checks; `verify` additionally
refreshes generated verification and portal artifacts. Add `--live` for the
bounded managed-gateway checks or `--ssh-journey` for the explicit bastion
journey. Checks requiring separate operator, recovery, or product-acceptance
evidence are intentionally omitted. `doctor` remains the deeper diagnostic
command and uses `CURRENT`, `ABSENT`, and `INCONSISTENT` to explain
projections against the current model revision.

For detailed firewall telemetry, appliance privilege, and portal boundaries,
see [the architecture guide](architecture.md), [the security model](security-model.md),
and the relevant advanced module page.
