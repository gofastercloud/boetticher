# Boetticher 0.5.2 release hardening

> Historical engineering record: `0.5.2` was an internal pre-release
> milestone, not a supported public release. The first supported release is
> numbered `0.1.0`; the labels and measurements below are retained unchanged.

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

The signed release manifest contains one exact content identity per artifact.
Maintainer output may additionally carry a qualification record, package
inventory, SBOM, smoke output, Trivy output, and provenance for transparency;
those are optional evidence attachments, not operator trust authorities.

The current reuse rule is based on artifact coordinates, effective build-input
identity, base dependency, and artifact bytes. `ArtifactPath` is only an
optional local cache hint; when it is absent, the resolver derives the fixed
cache path from artifact coordinates. Missing, malformed, or absent maintainer
evidence does not force a rebuild; the native maintainer path reports that
condition as `qualification-needed`. Changed effective build inputs or wrong
bytes are reported as `rebuild-needed` and never reuse the old artifact.

## PKI and operator baseline

The remaining `internal/pki` implementation generates the root and issuing
authorities, creates CRLs, and supports the deliberate browser/device client
certificate create/export/revoke path. Endpoint service certificates are now
issued and renewed by the unprivileged Smallstep CA on `lab-dns-01`; endpoint
private keys stay on their owning guest. The controller no longer signs
endpoint CSRs or persists managed endpoint certificate caches. Runtime PKI
directories and `generated/pki` therefore describe only deliberate operator or
kiosk identities and revocation projections.

The current default service model contains deliberate client-certificate/mTLS
consumers in logging, the Bifrost model canary, bounded journal-query access,
network probes, kiosk, and browser/device access. Pulse, StreamDeck, and the
controller-facing AIOps paths use scoped application credentials. Each
remaining certificate path has an explicit endpoint owner and threat-model
reason; the controller no longer carries a generic endpoint certificate cache
or endpoint CSR signer.

The current normal clean-install path is approximately:

```text
init -> bundle import/update -> enroll -> plan -> deploy -> status
```

The target operator path is:

```text
init -> enroll -> update -> deploy -> status
```

The optional Companion is a separate post-setup journey:

```text
companion add --mac MAC -> deploy -> companion setup -> companion status
```

`companion add` records the physical `eth0` identity in desired state and
derives `lab-display-01` at `10.10.20.50` on SERVERS. It performs no live
mutation. The explicit deploy applies the DHCP/DDNS reservation and exact
bastion destination before setup reaches the Pi through that route. HOME-side
addresses are not part of the persisted Companion contract.

The live baseline has not yet measured prompt count or elapsed operator
journey. Current enrollment still exposes bootstrap address, operator-key,
known-hosts, Proxmox CA, recovery/storage confirmations, and physical trunk
selection as explicit controls. The 0.5.2 work should keep the controls for
automation while deriving or guiding them in the normal interactive path.

The current operator controller uses the Boetticher binary, system SSH, and
Ansible for deployment. It does not require the native image builder. Smallstep
`step`/`step-ca` are not present in the frozen operator baseline.

The current 0.5.2 source checkpoint has added the pinned Smallstep binaries to
the appliance build inputs, staged an unprivileged `step-ca` service on
`lab-dns-01`, and moved server-leaf issuance and renewal for Pulse, Gatus,
Bifrost, Printer, Arr, AIOps, and the logging services to endpoint-owned
Smallstep operations. Companion, controller, and AIOps Pulse read/write paths
use scoped tokens. The remaining client-certificate consumers are
explicit exceptions: browser/kiosk access, the Bifrost model canary, bounded
journal-query access, and the logging transport itself. Their identities remain
endpoint-owned where applicable and are not part of the default topology.

The interactive operator journey now permits `deploy` to render a fresh live
plan and request an explicit `APPLY` approval. Supplying `--plan DIGEST` remains
required for non-interactive runs and for exact scripted qualification.

At source checkpoint `50335db`, the repeatable measurements are:

| Measure | 0.5.2 checkpoint |
| --- | ---: |
| Controller source LOC | 43,387 |
| Controller test LOC | 22,802 |
| Compiled repository packages | 50 |
| Controller dependency closure | 1,139 |
| Stripped controller | 53,765,410 bytes |
| Public command entries | 9 |
| Advanced command entries | 21 |
| Default Proxmox guests | 3 |
| Signed release artifact identities | 13 |
| Fresh site generated projections | 9 |
| Ansible roles | 17 |
| Unreachable functions | 0 |
| PKI implementation LOC | 580 |
| PKI test LOC | 126 |
| Non-test mTLS reference files | 17 |
| Lines changed from frozen 0.5.1 checkpoint | 2,188 added / 1,677 deleted |

The full local `make ci` gate passed at `24eb715`; the current maintainer-only
source-packaging addition passed its focused artifact test and shell checks.
This is source and local qualification evidence only; hosted release evidence,
live Proxmox qualification, and Companion qualification remain outstanding.

## Frozen default topology

The default plan contains exactly:

```text
lab-fw-01
lab-dns-01
lab-monitor-01
```

The Companion is external, optional, and absent from the default plan until its
physical Ethernet MAC is added. The reference physical qualification will
enable the selected second NIC as the `vmbr1` VLAN trunk during initial
enrollment, preserve HOME management on `vmbr0`, then add and deploy the fixed
SERVERS reservation before configuring the Pi.

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
