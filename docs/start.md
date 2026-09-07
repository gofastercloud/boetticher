---
layout: default
title: Start here
section: start
description: The Controller and Host lifecycle.
---

# Start here

Boetticher has two core targets:

- the Controller, which runs Boetticher, owns its administrative identity, and
  manages attached Controller hardware; and
- one Proxmox Host, whose OS baseline, storage, and virtual network are Host
  configuration.

There is no separate base or foundation object.

## First Host journey

Run these commands on the Controller after installing the supported release:

```sh
sudo boetticher controller bootstrap --operator pi --confirm-key-login
sudo boetticher controller status

sudo boetticher host create-identity
sudo boetticher host show-public-key
sudo boetticher host import-host-key \
  --address 192.0.2.10 --key 'ssh-ed25519 VERIFIED_HOST_KEY'
sudo boetticher host enroll root@192.0.2.10

sudo boetticher host plan-storage
sudo boetticher host apply \
  --data-disk /dev/disk/by-id/EXACT_DATA_DISK --yes
sudo boetticher host status --details
```

The Host key must be verified independently before `import-host-key`. Boetticher
never accepts a new key automatically. The Controller keeps its Ed25519 identity
and known-hosts file under `/var/lib/boetticher/controller/ssh/`.

`host apply` is declarative and idempotent. It inspects native state and then:

- applies the bounded Proxmox OS baseline;
- configures the exact dedicated data-disk layout when requested; and
- configures the VLAN-aware internal bridge while preserving HOME management.

It does not deploy Modules. An already-correct Host is a successful no-op.

## Approval boundaries

Host apply stops before a missing trust binding, a destructive disk operation,
or adoption of a compatible but unowned internal bridge.

Review a disk candidate first:

```sh
sudo boetticher host plan-storage
```

Then bind the exact stable identity and approve the operation:

```sh
sudo boetticher host apply \
  --data-disk /dev/disk/by-id/EXACT_DATA_DISK --yes
```

If an existing portless VLAN-aware `vmbr1` is compatible but unowned, review it
and explicitly approve adoption:

```sh
sudo boetticher host apply --adopt-existing-network --yes
```

Conflicting or ambiguous native state stops without mutation. Rerun `host apply`
after resolving the reported boundary; no workflow state, resume token, plan
digest, ledger, or transaction database is required.

## Host status

`host status` is the single normal Host view and is read-only. It reports
enrollment, Host configuration, storage, the internal network, the physical LAB
interface, and Module state. `--details` adds the node/version, guests, storage,
stable disks, LVM, mounts, interfaces, bridges, and routes.

The protected HOME path remains separate from the internal bridge. The current
reference topology is `vmbr0` for management and a VLAN-aware `vmbr1` for VLANs
5, 10, 20, 30, 40, and 99. Physical LAB networking is later Host configuration;
it is not a Module.

## Host teardown and rebuild

Teardown removes exact Boetticher-owned Host configuration while preserving the
Controller, imported Host trust, Proxmox installation, boot disk, HOME
management, and independent recovery access.

Review first:

```sh
sudo boetticher host teardown --plan
```

If the dedicated data disk is owned and will be erased, provide the exact
configured stable identity and ordinary approval:

```sh
sudo boetticher host teardown \
  --data-disk /dev/disk/by-id/EXACT_DATA_DISK --yes
```

After teardown, the Host configuration is `NOT CONFIGURED` while Host trust is
preserved. Rebuild through the proven sequence:

```sh
sudo boetticher host enroll root@192.0.2.10
sudo boetticher host apply --data-disk /dev/disk/by-id/EXACT_DATA_DISK --yes
sudo boetticher host status
```

Teardown is retryable. Unknown guests, storage, bridges, or configuration stop
the operation; no direct Proxmox cleanup is part of the supported journey.

## Reboots

Reboot the concrete target explicitly:

```sh
sudo boetticher controller reboot --yes
sudo boetticher host reboot --yes
```

The current reference architecture is IPv4-only. The retained guest IPv6 bridge
regression is internal to the vmbr1 implementation and is not a supported Host
command or acceptance journey. IPv6 forwarding and security policy belong to
explicit future firewall/network Module work.

## Modules

Modules are operator-visible capabilities on the Host. Their public grammar is
always:

```text
boetticher module <capability> <action> [flags]
```

The supported client-service order is `module firewall apply`, `module dns
apply`, then `module dhcp apply`. DHCP-derived DNS and client-facing NTP are
supporting behaviour of those two capabilities, not standalone Modules.
Provider software, appliance names, daemons, guests, and Controller
peripherals are not Module namespaces. Use the bounded resource commands under
`module dhcp` and `module dns`; arbitrary provider configuration is not part of
the public grammar.

## Recovery boundary

For Controller failure, restore `/etc/boetticher/` and
`/var/lib/boetticher/controller/ssh/`, or enroll a replacement Controller with
the independent Host trust ceremony. For Host failure, use independent
Mac/root recovery access, inspect native state, and rerun the bounded operation
only when Boetticher ownership is clear.

The [Controller guide](controller.html) covers local installation and
maintenance. The [lab guide](lab.html) describes the fixed Host topology.
