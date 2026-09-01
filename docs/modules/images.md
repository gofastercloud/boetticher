# Appliance images

Official appliances derive from the pinned Debian 13 boetticher base. The base
uses the Debian main and security snapshots `20260825T000000Z`; those inputs
are recorded in the base definition/runtime sources and the builder disables
snapshot metadata expiry checks.

## Hosted builder

The normal bootstrap build environment is the transient Core VM
`lab-builder-01` (VMID 190) on `vmbr0`. It uses 4 vCPUs, 8 GiB of memory, a
32 GiB root disk, and requires at least 20 GiB free before construction. It
receives the allow-listed public build bundle and pinned public inputs. It does
not receive site configuration, SOPS/Age identities, CA keys, runtime
credentials, or Git write credentials.

The same first-party build implementation supports `make image-check`,
`make images`, and the hosted bootstrap workflow. `image-check` validates
definitions without constructing appliances. `make images` constructs real
Linux artifacts in a supported Linux build environment; macOS controllers use
bootstrap to construct them in VM 190. Hardware construction is an advanced
release activity and is separate from the normal operator workflow.

Each construction attempt that needs a build starts with a fresh proven VM
190. The builder is destroyed after successful retrieval or bounded failure
diagnostics, and its exact cloud-init snippets and disposable `known_hosts`
file are cleaned up. A valid controller cache with a matching build record and
content hash avoids creating the builder. Missing, stale, or mismatched build
records require a fresh construction.

The builder also receives a separately allocated `local-lvm` cache volume
under reserved owner identity VMID 191. It is mounted at
`/var/cache/boetticher` and holds verified downloads, APT archives, Python
packages, and Go build/module caches. Cleanup detaches this volume before
destroying VM 190, so the next fresh builder can reuse it without making the
Proxmox management plane or user workloads part of the cache lifecycle.

The builder receives an artifact target list derived from the resolved plan.
The base, enabled module appliances, and managed firewall are built
and qualified; disabled optional modules such as Tailnet Router and Bifrost
(including its lightweight Bifrost implementation) are not constructed during
the default workflow. The memory-heavy base and
firewall stages run sequentially on the bounded builder; after they complete,
independent LXC workers use bounded concurrency of two. Each worker has its
own root filesystem, temporary build directory, log, and cleanup trap; a
failed worker fails the complete build.

Bootstrap and the builder print bounded timing lines for work that actually
ran. Successful builder runs also return `build-timings.log` and
`scan-timings.log` under generated artifact state, together with the builder
CPU/memory/disk configuration, so serial and parallel qualification runs can
be compared without treating timing as desired-state evidence.

Bootstrap's private JSON report identifies artifact stages with `phase`,
`kind`, and `target` fields. A cache hit is recorded separately from a cache
check and a cold builder run, which makes warm and cold bootstrap comparisons
less guessy.

The builder emits artifact inventory and compression measurements for each LXC
artifact. They include apparent and allocated rootfs bytes, regular-file count,
compressed bytes, zstd level, wall and CPU time, compression ratio, and the
enclosing artifact-build duration. The standalone
`scripts/benchmark-artifact-compression.sh ROOTFS OUTPUT_DIR` harness repeats
packaging against a qualified rootfs with plain tar and selected zstd levels;
set `BOETTICHER_BENCHMARK_ZSTD_LEVELS` and
`BOETTICHER_BENCHMARK_INCLUDE_PLAIN=0` to narrow a run. It writes only under
the requested output directory and does not replace the normal qualified
artifact. Normal builds use zstd level 3, selected after comparing the
historical level 19 against lower levels on a qualified artifact: lower levels
preserve the same tar/zstd format and checksum gate while avoiding a large
compression CPU cost for a modest delivery-size increase. Set
`BOETTICHER_ZSTD_LEVEL` only for a measured release experiment; compare
end-to-end delivery before changing the default transport or zstd level.

Builder output is streamed to the controller and artifact uploads are streamed
to Proxmox. Extraction rejects traversal, links, unsupported entries, excess
entries, and excessive expanded output. Artifact binaries remain runtime/cache
state and are ignored by initialized site repositories.

## Artifact build gate

Definition SHA-256 identifies the deterministic recipe: module, version,
architecture, guest kind, base identity, and pinned build inputs.
Content SHA-256 is the independently verified checksum of the actual built
bytes. Deployment requires the expected definition identity, that verified
content checksum, successful build smoke checks, a completed Trivy scan, and
passing Trivy secret and fixable-CRITICAL policy checks.

Builds may also emit a package manifest, SBOM, human-readable Trivy report, and
builder/tool provenance. These are useful diagnostic and release outputs;
they are not additional desired-state authorities, independent deployment
authorities, or recovery authority. Builder provenance is optional and does
not block an otherwise valid artifact.

The pinned Trivy version prepares its vulnerability database once, then
performs one full filesystem scan per artifact with vulnerability and secret
scanners enabled; parallel workers skip database updates so they cannot race
on the shared cache. Its JSON result is converted into the human-readable
summary and CycloneDX SBOM without rescanning the root filesystem. The timing
output records the one-time database preparation separately. DNS package
installation coalesces PowerDNS, SQLite, and Chrony into one repository
transaction.

Build timestamps, tool versions, and content hashes are not canonical
desired-state inputs. Artifact compression and transport settings are builder
implementation details; change them only with a separate, measured release
review.

Root filesystems are immutable and replaceable; declared persistent volumes are
attached independently and are not included in the artifact binary.
