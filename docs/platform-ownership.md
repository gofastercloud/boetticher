# Platform ownership

boetticher owns the platform. Proxmox owns the user's homelab.

boetticher manages only declared platform resources: the Proxmox host, managed
gateway when selected, DNS/NTP guests, monitor, portal, owned bridge/VLAN
configuration, firewall policy, Kea, PKI, SOPS state, SSH bastion policy,
Pulse monitoring state, platform backups, and generated platform state.
The firewall telemetry database is part of the managed firewall's declared
platform state; its API is a read-only consumer boundary for Pulse and future
internal AIOps tooling.

Arbitrary user VMs and LXCs remain outside the model, Boetticher's guarded
Proxmox provisioning plan, Ansible inventory, monitoring ownership, backup
guarantee, and deletion logic. Pulse may
display them when the Proxmox API exposes them, but they may use
the provided network simply by attaching a NIC to `vmbr1` and selecting a VLAN:

Platform guests carry canonical `boetticher` and `managed` tags. The `backup`
tag marks a declared platform guest for the platform backup projection; it is
metadata and does not cause user workloads to be adopted or backed up.

The generic `monitoring-agent` tag is the Pulse host-agent installation signal.
It is attached to `lab-proxmox-01` by default. Only declared managed components
with that tag receive the host agent; the tag is absent from VM and LXC guests
by default.

```text
Create VM/LXC in Proxmox → attach to vmbr1 → choose a zone VLAN → boot
```

The workload receives the zone's gateway, DHCP, DNS, NTP, Internet policy, and
inter-zone isolation without a boetticher registration command. A lease-derived
DNS name is publication, not adoption. Unknown guests may be shown as
informational diagnostics, never as drift.

Reserved IDs are 100–199 for the platform, 200–499 for future official modules,
and 500–899 as the suggested user-workload range. There is no generic
`boetticher vm`, `lxc`, or `workload` lifecycle command.
