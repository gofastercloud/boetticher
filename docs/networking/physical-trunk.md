# Physical trunk

The logical architecture is fixed: `vmbr0` is the HOME/upstream bridge and `vmbr1` is the VLAN-aware internal trunk. A physical `vmbr1` member is optional. OPNsense remains the router and inter-zone firewall.

## Discovery and identity

`homelab preflight --live` reads the fresh Proxmox host through the recorded HOME-side bootstrap path. It identifies the upstream device from corroborating evidence: the current bootstrap address on `vmbr0`, the `vmbr0` physical member, the default-route path, and the active SSH path. If those signals disagree, preflight stops with:

```text
HOLD: upstream interface identity is ambiguous
```

Interface enumeration order, interface names, PCI order, MAC order, and link speed alone are never used as architectural identity. The generated discovery evidence records the observed name, MAC, driver, model, speed, carrier, addresses, and bridge membership. The site model persists the stable MAC/PCI binding; the current Linux name is observed state.

## One NIC

With only the physical upstream interface available, bootstrap creates:

```text
vmbr0  -> upstream physical interface
vmbr1  -> no physical member, VLAN-aware
```

This is supported `virtual-only` mode, not degraded health. Internal management remains available through the Proxmox SSH bastion. The portal and doctor report `Physical trunk: virtual-only` and `vmbr1 has no physical member`.

## Two NICs

If exactly one other physical Ethernet interface is unused and safe, bootstrap proposes it and can attach it automatically:

```text
vmbr0  -> eno1
vmbr1  -> enp5s0
```

The candidate must have no configured IPv4 address, no non-link-local IPv6 address, no default route, no bridge/bond membership, no management dependency, no bootstrap path, and a stable hardware identity. Carrier is not required: a clean disconnected NIC can be configured and is reported as `CONFIGURED` with `NOTICE no carrier detected`.

## Multiple NICs

If two or more eligible unused NICs remain, Lab-in-a-Box does not choose one. Review the preflight output and select explicitly:

```sh
homelab preflight --site my-homelab --live --trunk-interface enp5s0
homelab bootstrap --site my-homelab --trunk-interface enp5s0 --opnsense-iso VERIFIED_ISO --recovery-confirmed
```

The selected interface still passes every safety check. The later equivalent is:

```sh
homelab network trunk attach enp5s0 --site my-homelab
```

The command prints the proposed mapping first; `--confirm` is required before mutation.

## Attach and detach after installation

The bootstrap and later attach paths use the same planner, upstream protection, VLAN-aware bridge mutation, post-change validation, and rollback attempt. Detach also refuses to touch the current `vmbr0` member or the interface carrying the recorded bootstrap address.

```sh
homelab network trunk status --site my-homelab --live
homelab network trunk attach enp5s0 --site my-homelab --confirm
homelab network trunk detach enp5s0 --site my-homelab --confirm
```

After a change, the implementation verifies `vmbr0`, the upstream address/default-route path, VLAN-aware `vmbr1`, expected membership, and the platform bastion path where live endpoints exist. A failed mutation or uncertain rollback is reported as `HOLD`, never success.

## Renaming, replacement, and recovery

If Linux gives a known device a new name, doctor compares the persisted MAC/PCI identity and reports the rename without silently rewriting configuration. Review the proposed replacement, update the binding through the explicit trunk workflow, and regenerate projections. Do not manually edit unrelated bridges, bonds, VLAN interfaces, routes, Proxmox SDN, or user network configuration.

The managed switch must support an 802.1Q trunk and explicit access/native VLAN handling. Use switch/client isolation for physical SANDBOX peer isolation. If a network change loses access, retain the HOME path, use the recorded Proxmox endpoint and break-glass recovery procedure, and treat uncertain state as a recovery `HOLD`.
