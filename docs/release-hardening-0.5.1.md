# Boetticher 0.5.1 release hardening

This document records the reproducible comparison for the 0.5.1 release-hardening
work. It describes the resulting architecture and qualification evidence as the
work progresses; it is not itself release evidence.

## 0.5.0 baseline

Baseline source revision: `cce6289327302f12e870c6d305daeb6adb85463e` (`0.5.0` branch,
2026-09-04). The baseline tree contained no intentional source changes beyond
that revision. An untracked local `generated/` directory held maintainer output
and was excluded from the measurements and from version control.

The measurements below use the same repository tree, commands, and definitions
at the end of the 0.5.1 work. They are comparison metrics, not claims that the
0.5.0 branch was officially release-qualified.

| Measure | 0.5.0 baseline | Measurement definition |
| --- | ---: | --- |
| Controller source LOC | 45,629 | `rg --files cmd internal -g '*.go' -g '!**/*_test.go' \| xargs wc -l`; use the `total` row |
| Controller test LOC | 23,065 | `rg --files cmd internal -g '*_test.go' \| xargs wc -l`; use the `total` row |
| Compiled repository packages | 49 | `go list ./... \| wc -l` |
| Controller dependency closure | 1,140 | `go list -deps ./cmd/boetticher \| sort -u \| wc -l` |
| Release controller size | 53,899,362 bytes | Size of the stripped release controller built with `-trimpath -s -w` and the release trust root embedded |
| Default Proxmox guests | 6 | The `NewSite` default topology and the final clean-install guest inventory |
| Public command menu entries | 9 | Number of entries in `commandSpecs` in `internal/cli/commands.go` |
| Advanced command entries | 33 | Number of entries in `advancedCommandSpecs` in `internal/cli/commands.go` |
| Release bundle artifact identities | 14 | `tar -xOzf BUNDLE manifest.json \| jq '.artifacts \| length'` |
| Persistent generated site projections | 45 | Files below `SITE_DIR/generated`, excluding `artifacts`, `release`, and `runtime`; measured on the reference live site |
| Ansible roles | 17 | `find ansible/roles -mindepth 1 -maxdepth 1 -type d \| wc -l` |
| Unreachable functions | 24 | `go run golang.org/x/tools/cmd/deadcode@v0.47.0 -test ./...`; includes test-only and compatibility findings, which must be reviewed rather than blindly deleted |
| `go.mod` direct requirements | 13 | First parenthesized `require` block |
| `go.mod` requirement entries | 154 | Direct and indirect entries in `go.mod` |
| Module graph | 392 | `go list -m all \| wc -l` |
| Google/cloud API modules | 123 | Module graph entries beginning with `cloud.google.com` or `google.golang.org/api` |
| AWS SDK v2 modules | 19 | Module graph entries beginning with `github.com/aws/aws-sdk-go-v2` |
| Azure SDK modules | 6 | Module graph entries in the Azure SDK families |
| KMS-named modules | 2 | Module graph entries whose module name contains `kms` |
| Runtime mutation mechanisms | 4 | Local desired-state writes, Proxmox REST API, bounded privileged SSH, and Ansible playbooks |

The local controller-size comparison uses the same build flags, Go toolchain,
and source-default empty trust-data value. Hosted release-controller size is
separate evidence because release public-key material is not kept in this
repository. An unstripped development binary is not comparable to either
metric.

### Repeatable measurement procedure

Run from the repository root with the project-pinned Go toolchain and the local
cache paths used by the qualification environment:

```sh
GOCACHE=/private/tmp/boetticher-go-cache \\
GOMODCACHE=/private/tmp/boetticher-gomodcache \\
go list ./...

rg --files cmd internal -g '*.go' -g '!**/*_test.go' | xargs wc -l
rg --files cmd internal -g '*_test.go' | xargs wc -l
go list -deps ./cmd/boetticher | sort -u | wc -l
find ansible/roles -mindepth 1 -maxdepth 1 -type d | wc -l
go run golang.org/x/tools/cmd/deadcode@v0.47.0 -test ./...
```

For topology, use a fresh default `NewSite` plan and the authoritative live
Proxmox guest inventory. For release artifacts, inspect the final bundle
manifest rather than counting files in a build directory. For generated
projections, count only the explicitly named site-generated directory and keep
the exclusions unchanged. Runtime mutation mechanisms are an architectural
count: each mechanism must have a distinct authority and contract; wrappers or
call sites must not be counted as separate mechanisms.

## Evidence labels

Claims in this document use these boundaries:

- **Source-tested**: repository tests, static checks, or local build output.
- **Locally qualified**: a maintainer build or contract test performed on the
  development machine.
- **Live-qualified**: observed on the exact deployed revision and physical
  Proxmox/Companion test system.
- **Officially release-qualified**: proven by the hosted release workflow for
  one exact source revision and its signed artifacts.

One evidence level does not prove a higher level.

The official release workflow also binds the separately published controller
binary's exact SHA-256 and size into the signed bundle manifest, then checks
those values before publishing and proves that the release-built controller
imports that same bundle.

## 0.5.1 source checkpoint measurements

These are measured after the source hardening and before clean-install
qualification. They are not live or hosted release evidence. The generated
projection count is from a fresh default `init` output; the final table must be
repeated after clean-install deployment using the same exclusions.

| Measure | 0.5.0 baseline | 0.5.1 source checkpoint |
| --- | ---: | ---: |
| Controller source LOC | 45,629 | 43,512 |
| Controller test LOC | 23,065 | 22,532 |
| Compiled repository packages | 49 | 50 |
| Controller dependency closure | 1,140 | 1,139 |
| Release controller size, local trust-data build | 53,899,362 bytes | 53,765,378 bytes |
| Default Proxmox guests | 6 | 3 |
| Public command menu entries | 9 | 9 |
| Advanced command entries | 33 | 21 |
| Release bundle artifact identities | 14 | 13 |
| Persistent generated projections | 45 | 9 |
| Ansible roles | 17 | 17 |
| Unreachable functions | 24 | 0 |
| Runtime mutation mechanisms | 4 | 4 |
| Repository lines changed from baseline | — | 4,795 added / 6,919 deleted / -2,124 net |
| Direct Go requirements | 13 | 14 |
| Total Go requirement entries | 154 | 154 |
| Module graph | 392 | 392 |
| Google/cloud API modules | 123 | 123 |
| AWS SDK v2 modules | 19 | 19 |
| Azure SDK modules | 6 | 6 |
| KMS-named modules | 2 | 2 |
| Lines added in `origin/0.5.0...HEAD` | — | 4,209 |
| Lines deleted in `origin/0.5.0...HEAD` | — | 6,897 |
| Net repository change | — | -2,688 |

The direct-requirement increase is the explicit declaration of the already
transitive `golang.org/x/crypto` dependency used for the in-memory Apply
identity. SOPS/Age cloud/KMS transitive surface is unchanged because a smaller
replacement was not shown to preserve the current encryption and recovery
contract.

## Live qualification status

The 2026-09-04 read-only inspection after reinstall is a qualification hold,
not release evidence. The Proxmox host is reachable with no guests, the
internal NVMe holds the Proxmox root storage, and the stable 1 TB build disk is
present separately. The failing 2 TB disk is no longer attached. The managed
guest-storage PV/VG/LVM setup and the 0.5.1 platform deployment remain
NOT TESTED.

The Companion has not been reset or re-enrolled. Its previous HOME Wi-Fi and
SERVERS Ethernet state is therefore context only, not current 0.5.1 evidence.
No 0.5.1 source revision or release bundle has been deployed, so the
enroll/plan/Apply/revoke/commit lifecycle, interruption cleanup, recovery
usability, Companion journey, and idempotent second deployment remain NOT
TESTED.

## Local 0.5.1 test build

On 2026-09-04, all 13 checked-in appliance definitions completed image
construction, Trivy scanning, and smoke qualification through the isolated
native Linux maintainer path on T580. After the maintainer and documentation
changes reached exact source revision `98d362a`, the all-target build and
all-target qualification each reported 13/13 reusable artifacts and performed
no image construction or Trivy scan. Reuse required current definition/base
identity, artifact bytes, and complete qualification evidence.

This is local qualification only. It is not hosted release evidence and has
not been deployed to Proxmox or the Companion.

## 0.5.1 target lifecycle

The supported normal journey is:

```text
init -> enroll -> bundle import/update -> plan -> deploy -> status --details
```

The lifecycle has four authoritative state classes:

1. desired state: what the operator requests;
2. observed state: read-only facts from the enrolled system;
3. immutable operation state: the approved plan and bounded Apply journal;
4. last-applied state: the result Boetticher successfully committed.

Generated Ansible inputs, DNS and firewall files, SSH configuration, service
files, and documentation are disposable deterministic projections. They are
regenerated from authoritative state and are not additional lifecycle state.

Boetticher authority is deliberately separated into durable read-only/scoped
enrollment authority and temporary Apply authority. Apply keeps private
temporary-key material in memory while journaling the public key and bounded
cleanup targets before mutation, allowing an interrupted operation to use the
independent root path for cleanup. Independent operator/root recovery authority
is not Boetticher-owned and must survive enrollment, Apply, revoke,
interruption, and cleanup failure.

## Default topology decision record

This table records the 0.5.1 source decision. Live qualification still has to
prove that the resulting topology is the one deployed on the clean host.

| Component | Decision | Reason |
| --- | --- | --- |
| Portal | Remove | Its generated page duplicated the CLI/status path and required a dedicated guest and projection lifecycle. |
| Gatus | Optional | A status-page product is useful to some operators but is not required by the minimum control plane. |
| Central logging | Optional, default off | Logs remain available when enabled, without forcing a dedicated collector into every install. |
| DNS2 | Remove from default | A second guest on the same Proxmox host did not add a meaningful failure domain. |
| Pulse | Keep | It provides historical telemetry, Proxmox/guest health, an external health API, and Companion integration with scoped access. |
