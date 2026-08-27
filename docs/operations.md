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

## Deployment privilege

`labadmin` is an unprivileged durable SSH identity on Proxmox and appliances,
with only fixed read-only inspection helpers on the managed firewall. The
scoped Proxmox API token performs ordinary lifecycle operations. A
successful bootstrap supplies temporary root SSH access for deployment;
Ansible connects as root and does not use `become`. Convergence removes the
temporary guest keys and Proxmox host root allowance. A failed deployment
retains that access for retry, while cleanup failure is a hold. Operator root
access remains the break-glass bootstrap and recovery path.

## Portal versus monitoring

The portal is the human-readable projection of architecture, configuration,
runbooks, and the latest platform verification results. It is rebuilt after
successful platform commands and can be refreshed from non-secret status
metadata. It does not poll guests or reproduce graphs. Pulse owns metrics,
dashboards, synthetic checks, certificates, events, alerting, and
notifications.
