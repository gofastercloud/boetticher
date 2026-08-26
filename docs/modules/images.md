# Appliance images

Official appliances derive from the pinned Debian 13 boetticher base. The base
uses the Debian snapshot `20260327T000000Z`; the snapshot input is recorded in
the base definition and the builder disables snapshot metadata expiry checks.
On
macOS, bootstrap uses the transient Core builder `lab-builder-01` (VMID 190)
with bootstrap-only networking; it receives public build inputs and no Age,
CA, or runtime credentials. The builder is destroyed after artifact retrieval
and independent checksum verification.

Definition SHA-256 identifies the deterministic recipe. Content SHA-256 is
calculated from the actual built bytes and stored with package manifest, SBOM,
and Trivy evidence. An artifact without qualification evidence is `NOT BUILT`
and cannot be imported for deployment. Root filesystems are immutable and
replaceable; declared persistent volumes are attached independently.
