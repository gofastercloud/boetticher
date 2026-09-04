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

Version 0.1.0 keeps the everyday rhythm small: import a signed release bundle,
make a live plan, deploy that exact plan, and check the lab. StreamDeck now
lives on the external companion Pi rather than in a Proxmox guest.

## Start here

The [Boetticher guide](https://gofastercloud.github.io/boetticher/) is the nice
place to read: a short first-run walkthrough, a map of the lab, modules, and a
generated command menu.

## Quickstart

On a fresh host, replace `PROXMOX_HOME_IP` and the certificate path with your
real values:

```text
boetticher init --site-dir my-boetticher
boetticher enroll --site my-boetticher --bootstrap-address PROXMOX_HOME_IP --recovery-confirmed --proxmox-ca /path/to/pve-root-ca.pem
boetticher bundle import ./boetticher-0.1.0.tar.gz --site my-boetticher
boetticher deploy --site my-boetticher
boetticher status --site my-boetticher --live
```

Keep an independent copy of the age recovery identity created during setup.
The guide has the calm version of the rest.

The optional Companion is deliberately added after the core lab is healthy and
the guarded physical trunk is attached. Give Boetticher the Pi's physical
`eth0` MAC, deploy the derived SERVERS reservation and bastion route, then
configure the Pi at its fixed lab address:

```text
boetticher companion add --mac COMPANION_ETH0_MAC --confirm --site my-boetticher
boetticher deploy --site my-boetticher
boetticher companion setup --host-key 'ssh-ed25519 VERIFIED_HOST_KEY' --confirm --site my-boetticher
boetticher companion status --site my-boetticher
```

The fixed identity is `lab-display-01` at `10.10.20.50`; a HOME-side address is
not saved as the managed Companion endpoint.

## Built with a lot of excellent open source

Boetticher is the small connector between a pile of brilliant projects. Huge
thanks to [Proxmox VE](https://www.proxmox.com/), [Debian](https://www.debian.org/),
[Ansible](https://www.ansible.com/), [SOPS](https://github.com/getsops/sops),
[age](https://github.com/FiloSottile/age), [Pulse](https://github.com/rcourtman/Pulse),
[Blocky](https://github.com/0xERR0R/blocky), [PowerDNS](https://www.powerdns.com/),
[Chrony](https://chrony-project.org/), [WireGuard](https://www.wireguard.com/),
and every project named in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
They did the hard work; this project is grateful to stand on it.

Boetticher is released under the [Apache License 2.0](LICENSE). Please see
[CONTRIBUTING.md](CONTRIBUTING.md) if you would like to help, or
[SECURITY.md](SECURITY.md) if you have a security concern.
