# Security policy

Boetticher can affect network isolation, credentials, host access, backups,
and recovery. Please report suspected vulnerabilities privately.

## Reporting

Use the repository's GitHub Security Advisories channel when it is available.
If it is unavailable, contact the maintainer through the private contact
method listed in the GitHub profile before opening an issue.

Useful reports include:

- the affected revision and component;
- prerequisites and likely impact;
- reproduction steps that do not expose credentials; and
- a suggested mitigation, if you have one.

Never include secrets, private keys, live addresses, or sensitive site
configuration in a report. If a command displayed a credential, treat it as
compromised and rotate it through the supported recovery path.

## Disclosure and supported releases

Please give the maintainer reasonable time to investigate and coordinate a
fix before publishing details. This project does not publish a
formal supported-version matrix; reports against the current branch or latest
release are most useful. Vulnerabilities in Proxmox, Debian, nftables, Kea,
Pulse, Ansible, SOPS, age, PowerDNS, or another upstream should also be sent
to that project's security process.

## Scope

Boetticher scope includes the CLI, generated configuration, secret-boundary
handling, bootstrap transitions, ownership checks, SSH bastion policy, and
security-relevant portal or verification output. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for upstream links.
