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
bootstrap to construct them in VM 190. Hardware construction and the T580
workflow are `NOT TESTED` until executed.

Each construction attempt that needs a build starts with a fresh proven VM
190. The builder is destroyed after successful retrieval or bounded failure
diagnostics, and its exact cloud-init snippets and disposable `known_hosts`
file are cleaned up. A valid controller cache with a matching build record and
content hash avoids creating the builder. Missing, stale, or mismatched build
records require a fresh construction.

The builder receives an artifact target list derived from the resolved plan.
The base, enabled provider/module appliances, and managed firewall are built
and qualified; disabled optional modules such as Tailnet Router and LiteLLM
are not constructed during the default workflow. After the base root filesystem
is ready, independent LXC workers and the firewall worker use bounded
concurrency of two. Each worker has its own root filesystem, temporary build
directory, log, and cleanup trap; a failed worker fails the complete build.

Bootstrap and the builder print structured `timing stage=... duration_ms=...`
records. Successful builder runs also return `build-timings.log` and
`scan-timings.log` under generated artifact state, together with the builder
CPU/memory/disk configuration, so serial and parallel qualification runs can
be compared without treating timing as desired-state evidence.

Builder output is streamed to the controller and artifact uploads are streamed
to Proxmox. Extraction rejects traversal, links, unsupported entries, excess
entries, and excessive expanded output. Artifact binaries remain runtime/cache
state and are ignored by initialized site repositories.

## Artifact build gate

Definition SHA-256 identifies the deterministic recipe: module, version,
provider, architecture, guest kind, base identity, and pinned build inputs.
Content SHA-256 is the independently verified checksum of the actual built
bytes. Deployment requires the expected definition identity, that verified
content checksum, successful build smoke checks, a completed Trivy scan, and
passing Trivy secret and fixable-CRITICAL policy checks.

Builds may also emit a package manifest, SBOM, human-readable Trivy report, and
builder/tool provenance. These are useful diagnostic and release outputs;
they are not additional desired-state authorities, independent deployment
authorities, or recovery authority. Builder provenance is optional and does
not block an otherwise valid artifact.

The pinned Trivy version performs one full filesystem scan per artifact with
vulnerability and secret scanners enabled; its JSON result is converted into
the human-readable summary and CycloneDX SBOM without rescanning the root
filesystem. DNS package installation coalesces PowerDNS, SQLite, and Chrony
into one repository transaction.

Build timestamps, tool versions, and content hashes are not canonical
desired-state inputs. The current `zstd -T0 -19` artifact compression and gzip
transport remain the defaults. On a supported Linux builder, operators may
measure the Issue #22 compression candidates with
`BOETTICHER_ZSTD_LEVEL=10 make images`,
`BOETTICHER_ZSTD_LEVEL=15 make images`, and
`BOETTICHER_ZSTD_LEVEL=19 make images`; each successful LXC package emits its
compression duration and byte size in `build-timings.log`.
The controller-side bootstrap experiment
`BOETTICHER_BUILDER_TRANSPORT_COMPRESSION=plain boetticher bootstrap
--recovery-confirmed` selects an uncompressed tar stream for comparison; the
default gzip return stream is unchanged. Compare these measurements with the
artifact return transfer and deployment timings before changing either
default. The plain transport uses the same bounded, atomic, path-safe
extraction as gzip.

Root filesystems are immutable and replaceable; declared persistent volumes are
attached independently and are not included in the artifact binary.
