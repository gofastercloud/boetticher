# Physical trunk

`vmbr0` is the HOME/upstream bridge. `vmbr1` is the VLAN-aware internal bridge.
The logical design is fixed; physical NIC bindings are installation state.

`boetticher preflight --live` identifies the interface carrying the current
Proxmox default route and bootstrap connection. It never uses NIC numbering as
identity. Stable MAC/PCI information is retained, while the Linux name remains
observed state.

One NIC is a supported managed-mode installation:

```text
vmbr0 = upstream NIC
vmbr1 = VLAN-aware, no physical member
mode  = virtual-only
```

Managed mode remains virtual-only by default, so spare NICs stay unclaimed.
The operator may explicitly select and attach a physical trunk later. A
disconnected but otherwise clean NIC is eligible; carrier is not required.
External mode always requires a distinct physical trunk and an explicit
selection, even when exactly one eligible NIC remains, because the operator
appliance must receive VLANs 10, 20, 50, and 99.

For later changes use:

```text
boetticher network trunk status
boetticher network trunk attach IFACE
boetticher network trunk detach IFACE
```

The same planner protects the upstream address, default route, and bastion
path during bootstrap and later changes. An ambiguous binding is a stop, not a
guess. See [switch configuration](switch-configuration.md) for the downstream
requirements.
