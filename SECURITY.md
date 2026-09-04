# Security policy

Boetticher touches network boundaries, credentials, host access, backups, and
recovery. If you think you found a vulnerability, thank you—please tell us
privately so we can work on it without putting anyone else's lab at risk.

## How to report something

Use the repository's GitHub Security Advisories channel when it is available.
If it is not, contact the maintainer through the private method on the GitHub
profile before opening an issue.

The most helpful report includes:

- the affected revision and component;
- what needs to be in place for the problem to happen;
- a safe reproduction path; and
- the likely impact or a mitigation idea, if you have one.

Please leave out secrets, private keys, live addresses, private site files,
and exploit payloads. If a command printed a credential, stop using that
credential and rotate or revoke it through the supported recovery path.

## What happens next

We will acknowledge the report, investigate it, and coordinate a fix before
details are published. This is a small project without a formal supported
release matrix, so reports against the latest release or current main branch
are especially useful.

Problems in Proxmox, Debian, nftables, Kea, Pulse, Ansible, SOPS, age,
PowerDNS, or another upstream should also go through that project's security
process. Those maintainers know their software best.

## In scope

The Boetticher CLI, generated configuration, secret handling, bootstrap,
ownership checks, SSH bastion behaviour, and generated operator output are in scope. The
[third-party notices](THIRD_PARTY_NOTICES.md) link to the projects that do the
heavy lifting underneath.
