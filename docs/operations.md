# Operations

The CLI owns the product lifecycle:

```text
init → preflight → bootstrap → deploy → verify → doctor
                                      ↘ portal build
```

Use `bootstrap-endpoint` to record the known HOME-side Proxmox address, `preflight --live` to discover and classify physical NICs, `ssh-config` to render operator access, `network trunk` for the guarded physical-trunk transition, and `pki` for client certificates and trust export. The dedicated-data-disk layout is initialized as part of guarded `bootstrap`; `doctor --live` reports its Proxmox registrations and capacity. `upgrade` remains an explicit compatibility gate until schema and live migration qualification exists.

## How checks are reported

`boetticher verify` keeps generated SSH configuration, network reachability,
and a real authenticated SSH journey as separate checks. Local checks can pass
before a host is available; service journeys still need to be tried for real.
`boetticher doctor` reports each projection as `ABSENT`, `CURRENT`, or
`INCONSISTENT` against the current model revision, and separately reports
physical binding and unmanaged Proxmox guests.

Appliance binaries, scan roots, build caches, and qualification runtime state
are ignored in the private site repository. Keep those files in the bounded
controller artifact cache or regenerate them through the hosted builder. The
portable recovery set remains the site configuration, encrypted secrets,
recovery authority, and non-secret desired-state projections.

## Portal versus monitoring

The portal is the human-readable projection of architecture, configuration,
runbooks, and the latest platform verification results. It is rebuilt after
successful platform commands and can be refreshed from non-secret status
metadata. It does not poll guests or reproduce graphs. Pulse owns Proxmox API
inventory, metrics, availability checks, alerts, and notifications.
Boetticher verify and doctor remain authoritative for platform semantics.
