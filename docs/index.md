# Boetticher documentation

Choose the smallest guide that answers your question.

## Getting started

- [Installation](installation.md) walks through the first deployment on a
  fresh Proxmox host.
- [Operations](operations.md) covers the normal `deploy` → `status` workflow,
  updates, modules, backups, and safe next actions.
- [Troubleshooting](troubleshooting.md) explains common stops and where to
  look next.

## Using your homelab

- [Module configuration](modules/configuration.md) explains the operator
  configuration model and the shared module commands.
- [Module overview](modules/architecture.md) describes the built-in modules,
  including the optional [StreamDeck host display](modules/streamdeck.md).
- [Networking](networking/dhcp-dns-ntp.md), [physical trunks](networking/physical-trunk.md),
  and [external-firewall mode](networking/external-firewall.md) cover the
  decisions that belong to the operator.
- [Access](access/client-certificates.md) and [logs](operations/logs.md)
  explain supported interfaces.
- [Storage and recovery](storage/recovery.md) and the [recovery guide](recovery/recovery.md)
  explain what to preserve and how to rebuild.
- [Adding a workload](workloads/adding-a-workload.md) explains how
  operator-owned guests fit beside the platform.

## How it works

- [Architecture](architecture.md) describes the fixed network and platform
  services.
- [Security model](security-model.md) describes trust, privilege, and module
  boundaries.
- [Platform ownership](platform-ownership.md) explains what Boetticher manages
  and what remains yours.
- [State and determinism](state-model.md) explains desired state, generated
  projections, and live observations.
- [Command reference](commands.md) is generated from the CLI metadata.

## Maintainers and qualification

[Appliance images](modules/images.md), the [hardware checklist](hardware-test-checklist.md),
and the detailed security, storage, networking, and recovery pages are useful
when building, testing, or recovering the platform. They intentionally use
more precise implementation and verification language than the getting-started
guides.

The Pi companions have their own entry points: [kiosk](../pi/kiosk/README.md),
[StreamDeck](../pi/streamdeck/README.md), and [shared Pi configuration](../pi/base/README.md).
The Ansible directory documents its [configuration boundary](../ansible/README.md).

Future extension notes, such as the [Cloudflare](access/cloudflare.md) and
[WireGuard](access/wireguard.md) pages, are design notes rather than supported
0.4 installation paths.
