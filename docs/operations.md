# Operations

The CLI owns the product lifecycle:

```text
init → preflight → bootstrap → provision → converge → verify → doctor
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

Generated artifacts may be committed to the private site repository. Runtime state, OpenTofu state/plans/caches, bootstrap state, and temporary credentials remain outside Git.

## Portal versus Zabbix

The portal is the human-readable projection of architecture, configuration, runbooks, and the latest platform verification evidence. It is rebuilt after successful platform commands and can be refreshed from non-secret status metadata. It does not poll guests or reproduce graphs. Zabbix owns metrics, dashboards, synthetic checks, certificates, events, alerting, and notifications.
