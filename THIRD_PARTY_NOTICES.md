# Thanks, licences, and third-party notices

Boetticher is a small layer of glue around a lot of phenomenal open source.
The maintainers below built the software that makes this project possible. We
are grateful for their work.

Boetticher itself is released under the Apache License 2.0. Each upstream keeps
its own copyright, licence, and trademark rights. The table is a friendly map,
not a substitute for retaining the applicable licence and notice text when you
redistribute a controller, image, companion bundle, or copied source file.

## Controller components

These libraries are compiled into the controller. A redistributed controller
must include the licence and notice material supplied by the exact releases.

| Project | Pinned release | Licence / source |
| --- | --- | --- |
| [SOPS](https://github.com/getsops/sops) | 3.13.3 | [MPL-2.0](https://github.com/getsops/sops/blob/v3.13.3/LICENSE) |
| [age](https://github.com/FiloSottile/age) | 1.3.1 | [BSD 3-Clause](https://github.com/FiloSottile/age/blob/v1.3.1/LICENSE) |
| [modernc.org/sqlite](https://gitlab.com/cznic/sqlite) | 1.57.0 | Retain the module licence and SQLite notice; SQLite portions are public domain. |

The Go dependency graph also contains transitive modules. Before distributing a
release, generate an inventory from the locked module set and include the
notices it requires.

## Appliance and companion components

The image definitions pin or fetch these components:

| Project | Pinned release | Where it is used | Upstream notices |
| --- | --- | --- | --- |
| [Debian](https://www.debian.org/) | 13 / Trixie snapshot | Base and service images | Retain package licences and notices for the exact package set. |
| [Blocky](https://github.com/0xERR0R/blocky) | 0.34.0 | Client-facing DNS | [Release source and licence](https://github.com/0xERR0R/blocky/releases/tag/v0.34.0) |
| [PowerDNS Authoritative](https://github.com/PowerDNS/pdns) | 4.9.17 | Authoritative DNS | Review the exact package and source notices for the redistributed build. |
| [Pulse Community](https://github.com/rcourtman/Pulse) | 6.1.2 | Monitoring image and host agent | [MIT licence](https://github.com/rcourtman/Pulse/blob/v6.1.2/LICENSE) |
| [Gatus](https://github.com/TwiN/gatus) | 5.36.0 | Optional status page | [Release source](https://github.com/TwiN/gatus/releases/tag/v5.36.0); retain its licence and notices. |
| [LiteLLM](https://github.com/BerriAI/litellm) | 1.89.0 | HolmesGPT dependency in the optional AIOps image | Retain the application licence and locked Python dependency notices. |
| [HolmesGPT](https://github.com/HolmesGPT/holmesgpt) | 0.40.0 | Optional AIOps image | The image copies or extracts upstream source; retain its applicable licence and notices. |
| [OctoPrint](https://github.com/OctoPrint/OctoPrint) | 1.11.8 | Optional printer image | Retain the application licence and locked Python dependency notices. |
| [Tailscale](https://tailscale.com/) | 1.76.6 | Optional Tailnet Router image | Retain the package licence and repository notices. |
| [Ansible Core](https://github.com/ansible/ansible) | 2.19.1 | Controller runtime | [GPLv3 copying terms](https://github.com/ansible/ansible/blob/devel/COPYING) |
| [matthewpi/streamdeck](https://github.com/matthewpi/streamdeck) | commit `6586ce762db315c6633567f9a10ed4ef14fcd33e` | StreamDeck LXC | [MIT licence](https://github.com/matthewpi/streamdeck/blob/6586ce762db315c6633567f9a10ed4ef14fcd33e/LICENSE); retain exact Go dependency notices. |
| [python-elgato-streamdeck](https://github.com/abcminiuser/python-elgato-streamdeck) | pinned commit; runtime 0.10.0 | External Pi StreamDeck companion | Retain the source licence and notices for the pinned archive. |
| [Pillow](https://python-pillow.github.io/) and [HTTPX](https://www.python-httpx.org/) | 12.3.0 / 0.28.1 | External Pi StreamDeck companion | Retain their package licences and notices. |

The AI Router is Boetticher's in-tree Bifrost implementation. It provides the
OpenAI-compatible endpoint used by AIOps and does not bundle a separate router
runtime. The optional AIOps appliance has its own locked upstream dependency
set; retain the applicable notices when redistributing that artifact.

Base images also contain Debian packages such as systemd, OpenSSL, OpenSSH,
Kea, nftables, Chrony, nginx, and CA certificates. Their obligations depend on
the packages actually present in the built image. A redistributor should create
an artifact-level inventory from `dpkg`, Python lock files, and the Go module
closure before shipping images.

## A practical redistribution checklist

1. Retain the licence, copyright, and notice text for software that is really
   included in the thing you ship.
2. Generate the controller and image inventories from the exact locked inputs.
3. Check copied source, transitive packages, fonts, icons, and media as well as
   the obvious application packages.
4. Ask qualified legal counsel when a packaging question is unclear.

The thank-you list in the README is deliberately short. This page is the more
complete map, but neither one replaces the notices that belong in a shipped
artifact.
