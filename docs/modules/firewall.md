# Firewall backends

The managed gateway is one firewall capability with two packaging backends.
Core owns the gateway in managed mode regardless of backend. External-firewall
mode remains the existing explicit opt-out and does not create or manage a
gateway appliance.

| Backend | Isolation | Use | Qualification |
| --- | --- | --- | --- |
| `vm` | Separate guest kernel | Default, recommended, direct upstream/Internet-facing gateway | Current production-qualified baseline |
| `lxc` | Unprivileged container sharing the Proxmox kernel | Development, nested-router/double-NAT, and explicitly accepted lower-risk homelabs | Separate 0.5 qualification required; not VM-equivalent |

The omitted backend resolves to `vm`. Select the backend before bootstrap with
the generic typed configuration workflow:

```text
boetticher module configure firewall --set backend=vm --confirm --site ./my-boetticher
boetticher module configure firewall --set backend=lxc --confirm --site ./my-boetticher
```

There is no firewall-specific wizard, arbitrary backend string, privileged-LXC
mode, or privileged fallback. Invalid or unsupported LXC configuration holds
before mutation. `backend=lxc` changes guest packaging and kind only; it does
not change ownership, the fixed VMID, network topology, firewall policy, DHCP,
DNS publication, telemetry, monitoring, backup, or replacement contracts.

## LXC security contract

The LXC backend is supported only with the exact bounded profile below:

- `unprivileged=1`; `nesting=0`, `fuse=0`, `keyctl=0`, and `mknod=0`.
- Default Proxmox AppArmor/seccomp isolation remains enabled.
- No host mounts, host networking, custom hooks, arbitrary devices, broad
  feature flags, host-global sysctl or netfilter namespace mutation, or
  arbitrary cgroup/device access.
- Declared capabilities are exactly `CAP_CHOWN`, `CAP_NET_ADMIN`,
  `CAP_NET_BIND_SERVICE`, and `CAP_NET_RAW`. Systemd units apply narrower
  per-service bounding and ambient sets with `NoNewPrivileges=yes`.
- The resulting Proxmox guest identity, features, interfaces, service health,
  effective capability bounds, routing/NAT/DHCP behavior, and telemetry are
  verified. Any mismatch is a deployment `HOLD`; VM fallback is not attempted.

Both backends use the shared planner, semantic policy model, user-rule model,
nftables renderer, upstream observation/publication, Kea/DHCP policy,
telemetry IDs/comments, Ansible role, readiness checks, doctor/verify,
credentials, monitoring, backup, and replacement logic. Normal managed
gateway lifecycle rules therefore remain in force; disabling or purging a
required managed firewall is not an ordinary optional-module operation.

Use the VM backend for a direct upstream or Internet-facing gateway. Use LXC
only behind an additional boundary or for nested-router, double-NAT, and
explicitly accepted lower-risk homelab deployments; its shared kernel is not
an acceptable substitute for the VM isolation barrier.

The LXC backend is development for 0.5. It must not merge into the 0.4
acceptance/stabilisation baseline, and VM remains the only production-qualified
default throughout 0.4. Live Proxmox routing, DHCP, nftables, NAT, reboot,
replacement, telemetry, fail-closed, capability-isolation, and authenticated
journeys remain `NOT TESTED` until exercised in the 0.5 qualification matrix.
