# Boetticher 0.5.2 release hardening

This document records the reproducible 0.5.2 comparison and qualification
evidence. It is not itself release evidence.

## Frozen 0.5.1 baseline

Baseline source revision: `fbc682d` on `codex/0.5.1`. The 0.5.2 branch starts
from that pushed checkpoint. The untracked local `generated/` directory is
maintainer output and is excluded from source measurements.

The following commands run from the repository root with the project-pinned
Go toolchain and task-local caches:

```sh
GOCACHE=/private/tmp/boetticher-gocache \
GOMODCACHE=/tmp/boetticher-gomodcache \
go list ./...

rg --files cmd internal -g '*.go' -g '!**/*_test.go' | xargs wc -l
rg --files cmd internal -g '*_test.go' | xargs wc -l
go list -deps ./cmd/boetticher | sort -u | wc -l
find ansible/roles -mindepth 1 -maxdepth 1 -type d | wc -l
go run golang.org/x/tools/cmd/deadcode@v0.47.0 -test ./...
```

For topology, use a fresh default site plan and the authoritative Proxmox
inventory. For release artifacts, count `manifest.json` entries rather than
files in a maintainer cache. Generated projections exclude `artifacts`,
`release`, and `runtime` when measuring the site projection surface.

| Measure | 0.5.1 baseline |
| --- | ---: |
| Controller source LOC | 43,674 |
| Controller test LOC | 22,689 |
| Compiled repository packages | 50 |
| Controller dependency closure | 1,139 |
| Stripped controller with local trust data | 53,798,418 bytes |
| Public command entries | 9 |
| Advanced command entries | 21 |
| Default Proxmox guests | 3 |
| Signed release artifact identities | 13 |
| Fresh site generated projections | 9 |
| Ansible roles | 17 |
| Unreachable functions | 0 |
| Runtime mutation mechanisms | 4 |
| Repository delta from the frozen 0.5.0 baseline | 5,237 added / 6,994 deleted / -1,757 net |
| PKI implementation LOC | 832 |
| PKI test LOC | 330 |
| PKI top-level CLI entries | 2 |
| PKI client/trust operations | 4 |
| Non-test mTLS reference files | 31 |
| Certificate-request declarations | 15 |
| Non-test client-certificate issue/cache references | 22 |
| Module definitions | 11 |

The release bundle contains one top-level qualification record per artifact.
The standard artifact cache contains the artifact blob plus eight supporting
files, including build log, provenance, content checksum, package inventory,
SBOM, smoke output, and Trivy output. The portable release evidence currently
also contains a rewritten evidence record and signed manifest members. These
are four distinct representations of qualification identity to review:
artifact bytes, evidence record, evidence sidecars, and signed release
manifest.

The current reuse rule is based on artifact coordinates, effective build-input
identity, base dependency, artifact bytes, and complete qualification
evidence. The qualification statement now treats `ArtifactPath` as an
optional local cache hint rather than an identity field; when it is absent,
the resolver derives the fixed cache path from artifact coordinates. The
0.5.2 target is to preserve content-bound qualification while allowing
existing bytes to be requalified or have missing evidence regenerated where
supported, instead of treating a missing sidecar as an image-build failure.
The native maintainer path now reports that distinction explicitly: an existing
blob with missing or malformed qualification is preserved for scan-only
requalification, while a missing blob, changed build inputs, or wrong bytes
remain build failures.

## PKI and operator baseline

The bespoke PKI implementation is `internal/pki` plus controller-side
certificate and revocation caches. It currently generates the root and issuing
authorities, signs server and client CSRs, creates CRLs, manages client
certificate create/export/revoke commands, and persists certificate metadata
and revocation projections. A fresh current qualification site emits no PKI
files, but the source lifecycle supports `generated/pki`, runtime PKI identity
directories, certificate caches, and revocation caches.

The current default service model contains broad client-certificate/mTLS
consumers in logging, monitoring, AIOps, the TUI, network probes, kiosk, and
Companion/StreamDeck paths. The source baseline records 15 certificate-request
declarations and 31 non-test files containing mTLS or client-certificate
configuration. These references must be classified as removed, replaced by a
scoped application credential, or explicitly retained with a threat
justification before the old PKI code is deleted.

The current normal clean-install path is approximately:

```text
init -> bundle import/update -> enroll -> plan -> deploy -> status
```

The target operator path is:

```text
init -> enroll -> update -> deploy -> status
```

The live baseline has not yet measured prompt count or elapsed operator
journey. Current enrollment still exposes bootstrap address, operator-key,
known-hosts, Proxmox CA, recovery/storage confirmations, and physical trunk
selection as explicit controls. The 0.5.2 work should keep the controls for
automation while deriving or guiding them in the normal interactive path.

The current operator controller uses the Boetticher binary, system SSH, and
Ansible for deployment. It does not require the native image builder. Smallstep
`step`/`step-ca` are not present in the frozen operator baseline.

The current 0.5.2 source checkpoint has added the pinned Smallstep binaries to
the appliance build inputs, added deterministic Apple trust-profile export,
removed the unused Pulse reconciler identity, and made the Companion and
controller Pulse read paths token-only. The browser, logging, AIOps, and
module-specific mTLS paths remain pending classification or migration; the
Smallstep CA is not yet the issuance authority for those paths.

The interactive operator journey now permits `deploy` to render a fresh live
plan and request an explicit `APPLY` approval. Supplying `--plan DIGEST` remains
required for non-interactive runs and for exact scripted qualification.

At the pushed source checkpoint `0c2f80d`, the repeatable measurements are:

| Measure | 0.5.2 checkpoint |
| --- | ---: |
| Controller source LOC | 43,768 |
| Controller test LOC | 22,810 |
| Compiled repository packages | 50 |
| Controller dependency closure | 1,139 |
| Stripped controller | 53,781,890 bytes |
| Public command entries | 9 |
| Advanced command entries | 21 |
| Default Proxmox guests | 3 |
| Signed release artifact identities | 13 |
| Fresh site generated projections | 9 |
| Ansible roles | 17 |
| Unreachable functions | 0 |
| PKI implementation LOC | 807 |
| Lines changed from frozen 0.5.1 checkpoint | 642 added / 219 deleted |

The full local `make ci` gate passes at this checkpoint. This is source and
local qualification evidence only; hosted release evidence, live Proxmox
qualification, and Companion qualification remain outstanding.

## Frozen default topology

The default plan contains exactly:

```text
lab-fw-01
lab-dns-01
lab-monitor-01
```

The Companion is external and optional. The reference physical qualification
will enable the selected second NIC as the `vmbr1` VLAN trunk during initial
enrollment, while preserving HOME management on `vmbr0`.

## Evidence boundaries

- **Source-tested**: repository tests, static checks, and local builds.
- **Locally qualified**: maintainer artifact or bundle checks on the
  development host.
- **Live-qualified**: the exact deployed revision on the physical Proxmox and
  Companion test system.
- **Officially release-qualified**: the hosted release workflow for one exact
  source revision and its signed output.

No lower evidence tier proves a higher tier.

## 0.5.2 exit table

The same measurements will be repeated after PKI/evidence simplification and
clean-install qualification. The final decision will report both numerical
change and the resulting reduction in lifecycle concepts, operator steps,
and independent state representations.
