# Security policy

boetticher is infrastructure software. A defect may affect network isolation,
credentials, host access, backups, or recovery.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the repository
maintainer through the GitHub Security Advisories interface when it is
available. If that interface is unavailable, contact the maintainer through
the private contact method listed in the GitHub profile before opening an
issue. Do not include secrets, private keys, live addresses, or sensitive
configuration in a public issue.

Include the affected revision, component, prerequisites, impact, reproduction
steps that do not expose credentials, and any suggested mitigation.

## Scope

In scope are the boetticher CLI, generated configuration, secret-boundary
handling, bootstrap transitions, ownership checks, SSH bastion policy, and
security-relevant portal or verification output.

Upstream vulnerabilities in Proxmox, OPNsense, Zabbix, Ansible, OpenTofu,
SOPS, age, PowerDNS, AdGuard Home, or the operating system should also be
reported to those projects. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
for upstream links.

Never paste a credential shown by a command into an issue or chat. Treat it as
compromised, rotate it through the supported recovery path, and preserve only
non-secret evidence.
