# Appliance images

Official appliances derive from the pinned Debian 13 boetticher base. The base
uses the Debian snapshot `20260327T000000Z`; the snapshot input is recorded in
the base definition and the builder disables snapshot metadata expiry checks.

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
file are cleaned up. A valid controller cache with matching evidence and
content hashes avoids creating the builder. Missing, stale, or mismatched
evidence requires a fresh construction.

Builder output is streamed to the controller and artifact uploads are streamed
to Proxmox. Extraction rejects traversal, links, unsupported entries, excess
entries, and excessive expanded output. Artifact binaries remain runtime/cache
state and are ignored by initialized site repositories.

## Qualification evidence

Definition SHA-256 identifies the deterministic recipe: module, version,
provider, architecture, guest kind, base identity, and pinned build inputs.
Content SHA-256 is calculated from the actual built bytes and is stored with
byte size, package manifest, SBOM, Trivy reports, and builder provenance. The
provenance records the builder platform, input image, kernel, Go, Trivy,
mmdebstrap, libguestfs, qemu-img, architecture, and boetticher release where
available.

Only the qualification evaluator may mark evidence `Qualified=true`. The
controller independently recalculates the artifact and qualification-input
hashes before an artifact is accepted for deployment. An artifact without
qualification evidence is `NOT BUILT` and cannot be imported. Build timestamps,
tool versions, provenance, and content hashes are evidence rather than
canonical desired-state inputs.

Root filesystems are immutable and replaceable; declared persistent volumes are
attached independently and are not included in the artifact binary.
