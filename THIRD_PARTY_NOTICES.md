# Third-party notices

Boetticher is released under the Apache License 2.0. The source repository
does not vendor upstream target systems, but its controller and generated
appliance images contain or redistribute the software listed below. Each
project keeps its own copyright, licence, and trademark rights; these links
are references, not endorsements or certification.

## Controller components

These libraries are compiled into the controller and must retain the license
and notice material supplied by their exact releases when the controller is
redistributed.

| Project | Pinned release | License / source |
| --- | --- | --- |
| [SOPS](https://github.com/getsops/sops) | 3.13.3 | [MPL-2.0 license](https://github.com/getsops/sops/blob/v3.13.3/LICENSE) |
| [age](https://github.com/FiloSottile/age) | 1.3.1 | [BSD 3-Clause license](https://github.com/FiloSottile/age/blob/v1.3.1/LICENSE) |
| [modernc.org/sqlite](https://gitlab.com/cznic/sqlite) | 1.57.0 | Retain the module's license and SQLite notice; SQLite portions are public domain. |

The complete Go dependency graph includes additional transitive modules. The
repository currently does not ship a generated license inventory for that
graph; producing one from the locked module set is a prudent release task.

## Appliance and companion components

The 0.4 image definitions pin or fetch these components:

| Project | Pinned release | Where it is used | Upstream notices |
| --- | --- | --- | --- |
| [Debian](https://www.debian.org/) | 13 / Trixie snapshot | Base and service images | Retain the package licenses and notices for the exact Debian package set. |
| [Blocky](https://github.com/0xERR0R/blocky) | 0.34.0 | Client-facing DNS | [Release source and license](https://github.com/0xERR0R/blocky/releases/tag/v0.34.0) |
| [PowerDNS Authoritative](https://github.com/PowerDNS/pdns) | 4.9.17 | Authoritative DNS | Review the exact package and source notices for the redistributed build. |
| [Pulse Community](https://github.com/rcourtman/Pulse) | 6.1.2 | Monitoring image and host agent | [MIT license](https://github.com/rcourtman/Pulse/blob/v6.1.2/LICENSE) |
| [Gatus](https://github.com/TwiN/gatus) | 5.36.0 | Optional status page | [Release source](https://github.com/TwiN/gatus/releases/tag/v5.36.0); retain its license and notices. |
| [HolmesGPT](https://github.com/HolmesGPT/holmesgpt) | 0.40.0 | Optional AIOps image | The image copies/extracts upstream application source; retain the applicable source license and notices. |
| [OctoPrint](https://github.com/OctoPrint/OctoPrint) | 1.11.8 | Optional printer image | Retain the application license and the locked Python dependency notices. |
| [Tailscale](https://tailscale.com/) | 1.76.6 | Optional Tailnet Router image | Retain the package license and repository notices. |
| [Ansible Core](https://github.com/ansible/ansible) | 2.19.1 | Controller runtime | [GPLv3 copying terms](https://github.com/ansible/ansible/blob/devel/COPYING) |
| [matthewpi/streamdeck](https://github.com/matthewpi/streamdeck) | commit 6586ce762db315c6633567f9a10ed4ef14fcd33e | StreamDeck LXC | [MIT license](https://github.com/matthewpi/streamdeck/blob/6586ce762db315c6633567f9a10ed4ef14fcd33e/LICENSE); retain the exact Go dependency notices. |
| [python-elgato-streamdeck](https://github.com/abcminiuser/python-elgato-streamdeck) | pinned commit; runtime 0.10.0 | External Pi StreamDeck companion | Retain the source license and notices for the pinned archive. |
| [Pillow](https://python-pillow.github.io/) and [HTTPX](https://www.python-httpx.org/) | 12.3.0 / 0.28.1 | External Pi StreamDeck companion | Retain their package licenses and notices. |

The base images also contain Debian packages such as systemd, OpenSSL,
OpenSSH, Kea, nftables, Chrony, nginx, and CA certificates. Their exact
license obligations depend on the packages present in the built image, not
just this table. A redistributor should generate and ship an artifact-level
inventory from `dpkg`, the Python lock files, and the Go module closure before
shipping images.

## Required, prudent, and optional

Required for redistribution is retaining the applicable upstream license,
copyright, and notice text for software actually included in a controller,
image, companion bundle, or copied source file. The repository's links above
are not a substitute for those texts in a redistributable artifact.

It is prudent to automate the artifact inventory and check it against this
document before a release. Exact legal treatment of combined images, copied
source, and transitive packages needs review of the built artifacts and may
require legal advice; this file does not make that determination.

The short thanks in the README are optional acknowledgement, not a complete
license roll-call. No current vendored fonts, icons, images, submodules, or
legacy provider components were found in the source tree.
