---
layout: default
title: Start here
section: start
description: The Controller foundation lifecycle.
---

# Start here

Boetticher has one supported foundation path. Run these commands on the
Controller, in order, from a clean Raspberry Pi OS Lite (Debian 13/Trixie,
ARM64) installation:

```text
1. Install the Controller release payload.
2. Bootstrap the Controller.
3. Establish Proxmox host trust from the independently verified Mac record.
4. Enroll the Proxmox node.
5. Prepare the host baseline.
6. Recognize or initialize the dedicated data disk.
7. Recognize or configure the virtual internal network.
8. Check foundation status.
```

## Commands

```sh
sudo boetticher controller bootstrap --operator pi --confirm-key-login
sudo boetticher controller status

sudo boetticher host identity create
sudo boetticher host trust import --address 192.168.4.5 --key 'ssh-ed25519 VERIFIED_HOST_KEY'
sudo boetticher host enroll root@192.168.4.5
sudo boetticher host status
sudo boetticher host prepare

sudo boetticher storage plan
sudo boetticher storage initialize \
  --device /dev/disk/by-id/ata-Timetec_MS21_PL220510SCC1TB0785 --confirm

sudo boetticher network plan
sudo boetticher network configure --adopt-existing
sudo boetticher foundation status
```

The trust record is copied from the Mac only after a strict SSH connection to
the Proxmox address has been verified. Boetticher never accepts a new host key
automatically. The Controller keeps its Ed25519 identity and known-hosts file
under `/var/lib/boetticher/controller/ssh/`.

Storage initialization is the only foundation operation that can erase data.
Review the exact stable `/dev/disk/by-id` candidate and pass `--confirm` only
after verifying that it is neither the Proxmox boot disk nor a disk used by a
guest. If the native LVM and Proxmox layout is already the owned
`boetticher-data` store, `storage initialize` reports:

```text
Storage already initialized and healthy.
No changes required.
```

`vmbr1` is VLAN-aware, has no physical member, and has no host address. A
runtime IPv6 link-local address on a compatible pre-existing bridge is handled
by explicit adoption; configured addresses, gateways, physical members, or
unknown directives stop the operation. Adoption persists
`net.ipv6.conf.vmbr1.disable_ipv6=1` for the Proxmox host only. Guest IPv6
Ethernet forwarding remains a separate live acceptance check.

Once the explicit approvals are complete, use the guided read-only convergence
check:

```sh
sudo boetticher foundation converge
```

It reuses the same native checks as the individual operations, stops at any
missing trust, preparation approval, storage approval, or network adoption
decision, and reports `No changes required.` for an established foundation.
It never deploys a firewall, platform guests, physical trunk, or switch
configuration.

## Foundation teardown

To remove the Boetticher-owned foundation while preserving Controller trust,
the Proxmox installation, the boot disk, and HOME management, review the
read-only plan first:

```sh
sudo boetticher foundation teardown --plan
```

Teardown refuses unexpected guests, unknown storage, ambiguous bridges, and
unrecognized host configuration. The exact Timetec disk must be acknowledged
explicitly; `--yes` only confirms the non-destructive parts:

```sh
sudo boetticher foundation teardown \
  --confirm-storage /dev/disk/by-id/ata-Timetec_MS21_PL220510SCC1TB0785 \
  --yes
```

After teardown, `foundation status` reports Controller readiness and established
Proxmox trust, with host enrollment, baseline, storage, and network shown as
not configured. Rerun `host enroll`, `host prepare`, `storage initialize`, and
`network configure` to rebuild; no manual `pvesh`, LVM, network-file, or guest
cleanup is part of the supported journey.

For the bounded vmbr1 regression, run the native Controller test after each
rebuild and after each Proxmox reboot:

```sh
sudo boetticher network test bridge-ipv6
```

It creates two temporary guests on VLAN 40, proves bidirectional IPv6
link-local forwarding, and stops, destroys, and verifies removal of both
guests and their temporary storage volumes.

Approved reboot rehearsals use the Controller commands:

```sh
sudo boetticher foundation reboot --yes
sudo boetticher controller reboot --yes
```

## Recovery

For Controller failure, restore `/etc/boetticher/` and
`/var/lib/boetticher/controller/ssh/`, or enroll a replacement Controller with
the Mac trust ceremony. For Proxmox network failure, use independent Mac/root
access, inspect the native bridge and interface files, and restore the known
good bounded configuration. For partial storage, inspect native LVM and
Proxmox storage and rerun the operation only when its owned state is
recognized. No automated destructive recovery is provided.

The [Controller guide](controller.html) contains installation and maintenance
details. The [lab guide](lab.html) describes the fixed VLAN topology. Firewall
and application modules are later phases and are not required for foundation
readiness.
