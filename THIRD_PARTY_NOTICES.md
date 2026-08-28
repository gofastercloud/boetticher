# Third-party notices

boetticher is released under the Apache License 2.0. The project does not
vendor the systems below. It generates configuration, calls documented APIs,
or installs the operator-selected versions on the target platform. Each
upstream project keeps its own copyright, license, and trademark rights.

License details must be checked against the exact release artifacts installed
by an operator. The links below are the upstream project or licensing pages
used by this repository’s V1 design.

| Project | Maintainer / copyright holder | License | Role in boetticher |
| --- | --- | --- | --- |
| [Proxmox VE](https://www.proxmox.com/en/proxmox-virtual-environment) | [Proxmox project](https://git.proxmox.com/) and Proxmox Server Solutions GmbH | Majority AGPLv3 or similar FLOSS license; see the [Proxmox developer/licensing page](https://proxmox.com/en/about/open-source/developers) | Hypervisor, host networking, guest lifecycle, API, and native backups |
| [Pulse Community](https://github.com/rcourtman/Pulse/tree/v6.1.2) | Richard Courtman and Pulse contributors | [MIT](https://github.com/rcourtman/Pulse/blob/v6.1.2/LICENSE) | Core Proxmox API inventory, metrics, alerts, availability checks, and tagged-host hardware telemetry |
| [Ansible](https://www.ansible.com/) | Ansible community / Red Hat | [GPLv3](https://github.com/ansible/ansible/blob/devel/COPYING) | Guest configuration convergence |
| [SOPS](https://github.com/getsops/sops) | Mozilla and SOPS contributors | [MPL-2.0](https://github.com/getsops/sops/blob/main/LICENSE) | Encryption of site secrets |
| [age](https://github.com/FiloSottile/age) | age contributors | [BSD 3-Clause](https://github.com/FiloSottile/age/blob/main/LICENSE) | Operator identity and encrypted-secret recipient model |
| [PowerDNS Authoritative Server](https://www.powerdns.com/auth.html) | PowerDNS contributors | See the [PowerDNS source license notices](https://github.com/PowerDNS/pdns) for the exact release | Authenticated RFC2136 target for Kea-driven dynamic DNS |
| [modernc.org/sqlite](https://gitlab.com/cznic/sqlite) | The Sqlite Authors and modernc.org contributors | BSD 3-Clause; bundled SQLite portions are public domain; retain the module's `LICENSE` and `LICENSE-SQLITE` notices | Pure-Go SQLite driver for the managed firewall telemetry database |
| [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome) | AdGuard and contributors | [GPLv3](https://github.com/AdguardTeam/AdGuardHome/blob/master/LICENSE.txt) | Client-facing recursive/filtering DNS service |

## Trademarks and compatibility

Product names and logos belong to their respective owners. Mentioning a
project here means that boetticher is designed to interoperate with it; it
does not imply endorsement, certification, or a bundled distribution.

When redistributing a target image, package set, generated bundle, or other
artifact that contains upstream software, retain that artifact’s own license
and copyright notices in addition to this repository’s notices.
