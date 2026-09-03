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
| Controller source LOC | 45,500 | `rg --files cmd internal -g '*.go' -g '!**/*_test.go' \| xargs wc -l`; use the `total` row |
| Controller test LOC | 22,981 | `rg --files cmd internal -g '*_test.go' \| xargs wc -l`; use the `total` row |
| Compiled repository packages | 49 | `go list ./... \| wc -l` |
| Controller dependency closure | 1,140 | `go list -deps ./cmd/boetticher \| sort -u \| wc -l` |
| Release controller size | 53,899,362 bytes | Size of the stripped release controller built with `-trimpath -s -w` and the release trust root embedded |
| Default Proxmox guests | 6 | The `NewSite` default topology and the final clean-install guest inventory |
| Public command menu entries | 9 | Number of entries in `commandSpecs` in `internal/cli/commands.go` |
| Advanced command entries | 33 | Number of entries in `advancedCommandSpecs` in `internal/cli/commands.go` |
| Release bundle artifact identities | 14 | `tar -xOzf BUNDLE manifest.json \| jq '.artifacts \| length'` |
| Persistent generated site projections | 45 | Files below `SITE_DIR/generated`, excluding `artifacts`, `release`, and `runtime`; measured on the reference live site |
| Ansible roles | 18 | `find ansible/roles -mindepth 1 -maxdepth 1 -type d \| wc -l` |
| Unreachable functions | 24 | `go run golang.org/x/tools/cmd/deadcode@v0.47.0 -test ./...`; includes test-only and compatibility findings, which must be reviewed rather than blindly deleted |
| `go.mod` direct requirements | 13 | First parenthesized `require` block |
| `go.mod` requirement entries | 154 | Direct and indirect entries in `go.mod` |
| Module graph | 392 | `go list -m all \| wc -l` |
| Google/cloud API modules | 123 | Module graph entries beginning with `cloud.google.com` or `google.golang.org/api` |
| AWS SDK v2 modules | 19 | Module graph entries beginning with `github.com/aws/aws-sdk-go-v2` |
| Azure SDK modules | 6 | Module graph entries in the Azure SDK families |
| KMS-named modules | 2 | Module graph entries whose module name contains `kms` |
| Runtime mutation mechanisms | 4 | Local desired-state writes, Proxmox REST API, bounded privileged SSH, and Ansible playbooks |

The controller-size comparison must use the same build flags, embedded trust
root, Go toolchain, and dependency state. An unstripped development binary is
not comparable to the release-controller metric.

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
enrollment authority and temporary Apply authority. Independent operator/root
recovery authority is not Boetticher-owned and must survive enrollment, Apply,
revoke, interruption, and cleanup failure.

## Default topology decision record

This table is completed against the final 0.5.1 source and clean-install
qualification. Each retained default must have a current operational reason.

| Component | Decision | Reason |
| --- | --- | --- |
| Portal | Pending source review | |
| Gatus | Pending source review | |
| Central logging | Pending source review | |
| DNS2 | Pending source review | |
| Pulse | Pending source review | |
