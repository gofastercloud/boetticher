# Boetticher

<p align="center">
  <a href="https://gofastercloud.github.io/boetticher/"><img src="docs/images/boetticher-cover.jpg" alt="Boetticher: automated homelab builder" width="360"></a>
</p>

> Turn a clean Proxmox host into a proper little homelab—with networking, DNS,
> monitoring, backups, and the good bits already wired together.

Boetticher is a small, opinionated builder for a single-node Proxmox lab. You
describe the lab once, then use one friendly command-line tool to build it and
keep it humming. It looks after the platform around your workloads; your own
VMs and Linux Containers remain yours.

The name is a tiny chemistry-show wink. The result is less *Breaking Bad* and
more *breaking out the good gear*.

The supported lifecycle is Controller-driven: bootstrap the Controller, enroll
and prepare Proxmox, recognize or initialize dedicated storage, configure the
virtual network, and check the foundation. Application deployment and the
physical LAB trunk are later phases.

## Start here

The [Boetticher guide](https://gofastercloud.github.io/boetticher/) is the nice
place to read: a short first-run walkthrough, a map of the lab, modules, and a
generated command menu.

## Quickstart

On the Controller, use the following sequence. Replace the Proxmox address and
the verified host-key material with the values from the independent Mac trust
ceremony:

```text
boetticher controller bootstrap --operator pi --confirm-key-login
boetticher controller status
boetticher host identity create
boetticher host trust import --address PROXMOX_HOME_IP --key 'ssh-ed25519 VERIFIED_HOST_KEY'
boetticher host enroll root@PROXMOX_HOME_IP
boetticher host status
boetticher host prepare
boetticher storage plan
boetticher storage initialize --device /dev/disk/by-id/ata-Timetec_MS21_PL220510SCC1TB0785 --confirm
boetticher network plan
boetticher network configure --adopt-existing
boetticher foundation status
```

Use `boetticher foundation converge` after the first explicit approvals. It
repeats the native checks and reports `No changes required.` once the
foundation is established. It never approves trust or erases a disk for you.

## Built with a lot of excellent open source

Boetticher is the small connector between a pile of brilliant projects. Huge
thanks to [Proxmox VE](https://www.proxmox.com/), [Debian](https://www.debian.org/),
[Ansible](https://www.ansible.com/), [Pulse](https://github.com/rcourtman/Pulse),
[Blocky](https://github.com/0xERR0R/blocky), [PowerDNS](https://www.powerdns.com/),
[Chrony](https://chrony-project.org/), [WireGuard](https://www.wireguard.com/),
and every project named in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
They did the hard work; this project is grateful to stand on it.

Boetticher is released under the [Apache License 2.0](LICENSE). Please see
[CONTRIBUTING.md](CONTRIBUTING.md) if you would like to help, or
[SECURITY.md](SECURITY.md) if you have a security concern.
