---
layout: default
title: Modules
section: modules
description: The focused extras that make a Boetticher lab feel like your own.
---

# Modules: the fun stuff

Boetticher starts with the boring-but-useful lab plumbing already in place, then
lets you add a few focused extras. Modules are built into the release rather
than downloaded at runtime, so `module list` always shows the complete menu.

```text
boetticher module list --site ./my-boetticher
boetticher module configure printer --site ./my-boetticher
boetticher deploy --site ./my-boetticher
```

`module configure`, `module enable`, and `module disable` change the desired
settings in your site directory; deployment remains a separate, deliberate
step. Interactive deploy makes the live plan and asks you to approve it; scripted
deployments can still pass the exact digest explicitly.
`status --details` is the consolidated read-only operational view. Try
`--dry-run` whenever you want a preview without saving anything.

<figure>
  <img class="section-art" src="images/build-bench.webp" alt="Illustrated compact server and little rack on a warm homelab workbench">
  <figcaption class="art-caption">Small focused additions beat a giant pile of half-configured things.</figcaption>
</figure>

## The menu

| Module | Starts as | What it brings to the lab |
| --- | --- | --- |
| `dns` | always on | [Blocky](https://0xerr0r.github.io/blocky/) for client DNS, [PowerDNS](https://doc.powerdns.com/authoritative/) for names Boetticher owns, and [Chrony](https://chrony-project.org/) for time. |
| `logging` | off | An optional central, searchable systemd journal for managed appliance guests. The Proxmox host remains outside the guest upload path. |
| `monitoring` | on | [Pulse Community](https://github.com/rcourtman/Pulse) dashboards, Proxmox monitoring, and host telemetry. |
| `firewall` | on in managed-gateway mode | The Debian gateway, DHCP, dynamic DNS, routing, NAT, and zone rules. |
| `gatus` | off | A tidy status page for supported Boetticher services. It trusts the site CA for HTTPS endpoint checks. |
| `bifrost` | off | A lightweight, OpenAI-compatible AI endpoint. It currently serves AIOps. |
| `aiops` | off | [HolmesGPT](https://github.com/robusta-dev/holmesgpt) investigations that read alerts and journals, then leave a Pulse incident note. |
| `printer` | off | [OctoPrint](https://octoprint.org/) for one supported USB-connected printer. |
| `tailnet-router` | off | A small [Tailscale](https://tailscale.com/) subnet router for selected lab networks. |
| `airvpn` | off | An [AirVPN](https://airvpn.org/) WireGuard exit for a module that explicitly asks to use it. |

You still own your own VMs and LXCs. Use Proxmox for those workloads; give them
a NIC on `vmbr1`, choose a zone VLAN, and let DHCP take care of the ordinary
network settings. Boetticher does not try to adopt or run them for you.

## A quick configuration tour

`site.yml` is deliberately small. Start with the interactive command when you
can; it knows which questions each module actually needs.

```text
boetticher module configure gatus --site ./my-boetticher
boetticher module configure aiops --site ./my-boetticher
```

For automation, use `--non-interactive` with the required `--set`, `--usb`, and
`--secret` inputs, then add `--confirm`. `boetticher config validate` checks
the saved file, and `boetticher config show` prints the non-secret generated
configuration.

Here is the shape of a small AI and VPN setup. The names are examples; use the
aliases that make sense in your lab.

```yaml
modules:
  bifrost:
    enabled: true
    upstreams:
      - name: openrouter
        base_url: https://openrouter.ai/api/v1
        api_key_secret: openrouter_api_key
    models:
      - alias: operations-investigator
        upstream: openrouter
        model: your-provider/model
  aiops:
    enabled: true
    model_alias: operations-investigator
  airvpn:
    enabled: true
    servers: europe
```

Secrets are entered at a hidden prompt or on standard input, then kept in the
encrypted SOPS/age site material. Never put a key, token, or private key in
`site.yml` or on a command line.

## A few modules worth calling out

### Bifrost and AIOps

The `bifrost` module is the little AI traffic controller. Configure a named
OpenRouter (or other declared) upstream and a friendly model alias; AIOps then
uses that alias rather than knowing about a provider key or raw provider model
name.

AIOps is intentionally a curious investigator, not an auto-remediator. It can
read the things it needs to explain an alert and add a Pulse note. It does not
restart services, run shell commands, use SSH, or browse the Internet. Its
small request limits keep an enthusiastic incident from becoming a surprise
bill.

### AirVPN transit

Enable `airvpn` before selecting `network: airvpn` on a module that supports
network selection. On its first real deployment, Boetticher reads the local
AirVPN API key from `~/.secrets/btcr-airvpn.key`, requests one IPv4 WireGuard
profile for your `servers` selector, and stores the profile as the encrypted
site secret `airvpn_wireguard_config`.

Later deployments reuse that profile. Rotate it only when you mean to:

```text
boetticher module secrets airvpn rotate --confirm --site ./my-boetticher
boetticher deploy --site ./my-boetticher
```

Traffic from an AirVPN-selected module leaves through `lab-airvpn-01`
(`10.10.5.20`), not through the ordinary WAN path. Local services, DNS, NTP,
and modules using `network: direct` keep their usual routes. If the tunnel is
not up, the guest has no direct-Internet escape hatch.

### Hardware helpers

The printer module binds a named need to a stable physical USB port, rather
than to a device name that can change after a reboot. `module configure` will
show compatible choices. Generic USB export remains available for actual guest
peripherals such as printers and serial hardware.

StreamDeck is a capability of a Boetticher companion device, not a Proxmox
module. Attach the supported StreamDeck directly to the Companion Pi. The
Companion receives no Proxmox credentials or USB passthrough configuration.

On a 0.4 site, `boetticher companion migrate` can move the exact old
`lab-streamdeck-01` guest to this arrangement. A fresh 0.1.0 site has no such
guest to clean up.

After the core platform is healthy, add the physical `eth0` MAC to desired
state, deploy its fixed `10.10.20.50` SERVERS reservation and bastion route,
then set up the Companion from the signed release imported during bootstrap:

```text
boetticher companion add --mac COMPANION_ETH0_MAC --confirm --site ./my-boetticher
boetticher deploy --site ./my-boetticher
boetticher companion setup --host-key 'ssh-ed25519 VERIFIED_HOST_KEY' --confirm --site ./my-boetticher
boetticher companion status --site ./my-boetticher
```

### Names, dashboards, and logs

DNS is mandatory; logging is optional and off by default. Blocky answers client
DNS queries, PowerDNS owns Boetticher's private names, and Chrony supplies
Network Time Protocol (NTP). Add your own private A or CNAME records with
`boetticher dns record`, then deploy. Pulse is on by default; Gatus is an
optional, lighter status page for the HTTPS services Boetticher knows about.

## The small print, without the legalese

Every module has fixed resource names, networking needs, and storage needs.
That keeps the lab predictable and makes removal straightforward: disabling a
module keeps its data by default, while `--purge` is the explicit "yes, really"
button. Modules do not get a general Proxmox shell, arbitrary firewall rules,
or a grab-bag plugin system.

For the complete command forms, use the [command menu](commands.html) or run
`boetticher module --help`.
