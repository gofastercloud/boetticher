# Boetticher

<p align="center">
  <img src="docs/images/boetticher-cover.jpg" alt="Boetticher automated homelab builder" width="480">
</p>

Boetticher is an opinionated way to turn a small Proxmox host into a useful,
secure homelab without spending your weekend designing the platform underneath
it.

It gives a personal lab a sensible fixed layout, boring secure defaults, and
one small operator CLI. The platform includes a managed gateway, DNS/NTP,
monitoring, central logs, a static portal, backups, and recovery information.
Optional first-party modules add services such as a status page, an AI router,
read-only incident investigation, a Tailnet subnet router, OctoPrint, or a
quiet StreamDeck display for Proxmox host health.

Boetticher is deliberately small and opinionated. It is not Kubernetes, a
generic infrastructure framework, or a guest-management tool. Proxmox remains
the home for your own workloads; Boetticher manages only the platform resources
it declares.

## Why use it?

- Start with a clean Proxmox host and a platform that already has a shape.
- Keep the ordinary workflow to `init`, `deploy`, `status`, and a few focused
  commands when you need them.
- Use fixed network and guest identities that are easy to understand and
  recover.
- Add optional capabilities without handing a generic control plane ownership
  of your lab.
- Keep secrets on the controller, encrypted with SOPS/Age, and out of normal
  output and generated portal pages.

## What you need

- A fresh supported Proxmox VE installation on amd64 hardware.
- A macOS or Linux controller with the Boetticher binary, SSH, and Ansible
  Core. SOPS 3.13.3 and age 1.3.1 are included in the controller build.
- One Ethernet interface for the default managed, virtual-only setup. A
  second interface and a VLAN-aware switch are needed for a physical trunk or
  external-firewall mode.
- Enough storage for either the single-disk or dedicated-data-disk profile.

The platform is IPv4-only and designed for a single-node homelab. A fresh
installation is the supported starting point for 0.4; it does not silently
renumber or migrate an existing network.

## Quickstart

Install Proxmox and the Boetticher controller first. On a fresh host, the first
deployment establishes trust and storage once. After that, most changes are
`deploy` followed by `status`.

```text
boetticher init --site-dir my-boetticher
boetticher bootstrap-endpoint set PROXMOX_HOME_IP --site my-boetticher
boetticher preflight --site my-boetticher --live
boetticher bootstrap --site my-boetticher --recovery-confirmed --proxmox-ca /path/to/pve-root-ca.pem
boetticher deploy --site my-boetticher --dry-run --proxmox-ca /path/to/pve-root-ca.pem
boetticher deploy --site my-boetticher --proxmox-ca /path/to/pve-root-ca.pem
boetticher status --site my-boetticher --live
```

`PROXMOX_HOME_IP` is the address assigned by your existing upstream DHCP
server; it is an example placeholder, not a literal address. During bootstrap,
verify the Proxmox host fingerprint when SSH asks, keep an independent copy of
the Age identity, and review any dedicated-disk prompt before confirming it.
Deploy prints nine useful phases and finishes with one `PASS` or `FAIL`
summary. If it stops, the summary tells you what changed, whether temporary
authority was cleaned up, and the next command to run. See the
[installation guide](docs/installation.md) for the one-time details and the
[operations guide](docs/operations.md) for the everyday workflow.
The one-time `preflight` and `bootstrap` commands are part of the advanced
command surface; use `boetticher help --advanced` for their full forms.

For an external firewall, use `boetticher init --external-firewall` and follow
the [external-firewall contract](docs/networking/external-firewall.md) before
bootstrap. Managed mode is the simpler default and starts with a virtual-only
internal bridge.

## The design in one minute

Core keeps the architecture fixed: a Proxmox host, a managed Debian gateway
or an operator-owned external firewall, six small network zones, and
Boetticher-owned platform appliances. Modules are compiled into the release;
they declare bounded needs, while Core owns deployment, storage, secrets,
network policy, and recovery.

DNS has one built-in implementation: Blocky provides client-facing recursive
and filtering DNS, with PowerDNS Authoritative and Chrony behind it. Monitoring
uses Pulse Community. The platform's fixed internal namespace is
`lab.home.arpa`.

## Documentation

Use the [documentation map](docs/index.md) to choose the right depth:

- [Installation](docs/installation.md) — first deployment on a fresh host.
- [Operations](docs/operations.md) — modules, status, updates, backups, and
  safe next actions.
- [Modules](docs/modules/architecture.md) — built-in capabilities and their
  boundaries.
- [Recovery](docs/recovery/recovery.md) — what to keep and how to rebuild.
- [Architecture and security](docs/architecture.md) — the fixed design and
  its security boundaries.
- [Command reference](docs/commands.md) — generated from the CLI metadata.
- [Contributing](CONTRIBUTING.md) and [security reporting](SECURITY.md) — for
  people working on the project.

## License and thanks

Boetticher is released under the [Apache License 2.0](LICENSE). It stands on
excellent open-source work, including Proxmox VE, Debian, Pulse, Blocky,
PowerDNS, Ansible, SOPS, age, and the other projects listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Their names and marks belong
to their respective projects; Boetticher is independent and is not endorsed by
Proxmox or those upstreams.

This is early software. Experiment on hardware you can recover, keep backups,
and read the recovery guide before making changes you cannot easily undo.
