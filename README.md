# Boetticher

<p align="center">
  <a href="https://lab.davebarton.cc/"><img src="docs/images/boetticher-cover.jpg" alt="Boetticher: automated homelab builder" width="360"></a>
</p>

> Turn a clean Proxmox host into a proper little homelab—with networking, DNS,
> monitoring, VPN egress, and the good bits already wired together.

Boetticher is a small, opinionated builder for a single-node Proxmox lab. You
describe the lab once, then use one friendly command-line tool to build it and
keep it humming. It looks after the platform around your workloads; your own
VMs and Linux Containers remain yours.

The name is a tiny chemistry-show wink. The result is less *Breaking Bad* and
more *breaking out the good gear*.

The supported lifecycle is Controller-driven: bootstrap the Controller, enroll
the Proxmox Host, apply its OS baseline, storage, and virtual network, then
inspect the Host. Modules are operator capabilities applied afterwards; they
are not part of Host apply.

## Start here

The [Boetticher guide](https://lab.davebarton.cc/) is the nice place to read: a
short first-run walkthrough, a map of the lab, modules, and a generated command
menu. The [source remains on GitHub](https://github.com/gofastercloud/boetticher).

## Quickstart

After installing the Controller payload, run this sequence on the Controller.
Replace the Proxmox address and the host-key material with values verified
independently (the [Controller guide](docs/controller.md#verifying-the-host-key)
shows how):

```text
boetticher controller bootstrap --operator pi --confirm-key-login
boetticher controller status
boetticher host create-identity
boetticher host show-public-key
boetticher host import-host-key --address PROXMOX_HOME_IP --key 'ssh-ed25519 VERIFIED_HOST_KEY'
boetticher host enroll root@PROXMOX_HOME_IP
boetticher host plan-storage
boetticher host apply --data-disk /dev/disk/by-id/EXACT_DATA_DISK --yes
boetticher host status
```

Host apply is idempotent, reports `No changes required.` once the Host is
configured, and never accepts Host trust or erases a disk without exact
operator approval. [Start here](docs/start.md) is the canonical journey,
including approval boundaries, maintenance, teardown, and the Module order.

## Built with a lot of excellent open source

Boetticher is the small connector between a pile of brilliant projects. Huge
thanks to [Proxmox VE](https://www.proxmox.com/), [Debian](https://www.debian.org/),
[Ansible](https://www.ansible.com/),
[OpenWrt](https://openwrt.org/), [Stubby](https://github.com/getdnsapi/stubby),
[Quad9](https://quad9.net/), [WireGuard](https://www.wireguard.com/),
and every project named in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
They did the hard work; this project is grateful to stand on it.

Boetticher is released under the [Apache License 2.0](LICENSE). Please see
[CONTRIBUTING.md](CONTRIBUTING.md) if you would like to help, or
[SECURITY.md](SECURITY.md) if you have a security concern.
