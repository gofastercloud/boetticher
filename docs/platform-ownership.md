# Platform ownership

boetticher owns the platform. Proxmox owns the user's homelab.

boetticher manages only declared platform resources: the Proxmox host, managed
gateway when selected, DNS/NTP guests, monitor, portal, owned bridge/VLAN
configuration, firewall policy, Kea, PKI, SOPS state, SSH bastion policy,
Pulse monitoring state, platform backups, and generated platform state.

Arbitrary user VMs and LXCs remain outside the model, OpenTofu state, Ansible
inventory, Pulse monitoring ownership, backup guarantee, and deletion logic. They may use
the provided network simply by attaching a NIC to `vmbr1` and selecting a VLAN:

Platform guests carry canonical `boetticher` and `managed` tags. The `backup`
tag marks a declared platform guest for the platform backup projection; it is
metadata and does not cause user workloads to be adopted or backed up.

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
