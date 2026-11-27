---
layout: default
title: Controller
section: controller
description: Prepare the local Boetticher Controller.
---

# The local controller

The Controller is the only supported operator entry point. Bootstrap it first,
then use the Host commands below to enroll, apply, inspect, and recover the
Proxmox Host.

## Supported starting point

Use Raspberry Pi OS Lite based on Debian 13 (Trixie) with the 64-bit ARM64
userspace on a Raspberry Pi 3, 4, or 5-class board. Keep the existing hostname,
network placement, routes, SSH host keys, operator keys, and `pi` passwordless
sudo access unchanged. Test a new public-key SSH session before running the
installer; `--confirm-key-login` records that acknowledgement before password
authentication is disabled.

### Dual-homed Controller DNS

When the Controller has a LAB connection, accept that connection's DHCP DNS
and prefer it for resolving private service names. On NetworkManager, identify
the active connection by its LAB NIC MAC and reservation, rather than assuming
an interface name. Set that connection's `ipv4.ignore-auto-dns` to `no` and use
a lower positive `ipv4.dns-priority` than HOME (the reference setup uses `50`).
Reapply the connection and verify the resolver order. Keep HOME DNS as fallback
and retain HOME's default route; the LAB connection remains `never-default`.
These are Controller-local connection settings, separate from the DNS records
owned by `/etc/boetticher/lab.yml`.

## Install from a local payload

The maintainer payload contains a prebuilt ARM64 `boetticher` binary, its
private Ansible playbook and roles, the pinned Azlux public key, an installer,
and `SHA256SUMS`. It contains no site, credential, appliance, or
workstation-cache data.

Build it from a checkout with the pinned Go 1.26.10 toolchain
(`BOETTICHER_GO_BIN` selects it if `go` on `PATH` is another version) and the
reviewed upstream arrstack source tarball:

```sh
ARRSTACK_SOURCE_ARCHIVE=/path/to/arrstack-source.tar.gz \
  sh scripts/package-controller.sh BUILD_ID
```

The script writes `boetticher-controller-linux-arm64.tar.gz`, `install.sh`,
and `SHA256SUMS` to `dist/controller/`. Copy that directory to the Pi.

On the Pi, with the payload copied to `/home/pi/controller-release`:

```sh
sudo sh /home/pi/controller-release/install.sh \
  --from-dir /home/pi/controller-release \
  --operator pi \
  --confirm-key-login
```

The installer validates the OS and architecture, verifies the archive checksum,
installs a root-owned versioned release, prepares `/opt/boetticher/venv`, and
invokes the local controller bootstrap. A failed checksum or unsafe archive
leaves the previous installed release untouched. Repeating the same payload is
safe and does not edit an existing versioned release.

The eventual public form is intentionally documented without a fake location:

```sh
curl -fsSL "$RELEASE_BASE/install.sh" | \
  sudo sh -s -- --version "$VERSION" --operator pi --confirm-key-login
```

`RELEASE_BASE` must be a real, published HTTPS release location. Until one is
published, use `--from-dir`; the installer does not silently fall back to local
files after a failed download or checksum check.

### Keeping old releases tidy

The installer keeps versioned releases under `/opt/boetticher/releases` so the
`current` release can be swapped safely. It does not guess when an old release
is safe to remove. Run the cleanup helper to get a read-only report first:

```sh
sudo sh /opt/boetticher/current/controller/proxmox/libexec/cleanup-controller-storage.sh
```

Review the list, then choose an age and retention count and approve explicitly:

```sh
sudo sh /opt/boetticher/current/controller/proxmox/libexec/cleanup-controller-storage.sh \
  --keep-releases 2 --max-age-days 30 --yes
```

The helper refuses symlinked or non-root-owned releases and never removes
`current`, `rollback`, unknown names, or recent releases. Temporary controller
downloads can be reported with `--cache-root`; no live deletion happens without
`--yes`. On a Mac, point `--cache-root` at the task-local controller cache.

### Keeping the build workspace tidy

Packaging and image builds leave generated output under `generated/`. The
local helper only considers directly named stale trees (`artifacts-stale-*`,
`boetticher-build-*`, and `boetticher-download-*`). It reports first and keeps
the newest two trees:

```sh
sh scripts/cleanup-local-storage.sh --root generated
```

To approve removal after reviewing the report, choose the age explicitly:

```sh
sh scripts/cleanup-local-storage.sh --root generated --keep 2 --max-age-days 30 --yes
```

It refuses symlinks, unexpected names, and paths not owned by the current
user, and never touches anything outside the selected root.

## Bootstrap and status

```sh
sudo boetticher controller bootstrap --operator pi --confirm-key-login
sudo boetticher controller status
```

`controller bootstrap` runs one local Ansible playbook and then local readiness
checks. `controller status` is read-only: it does not repair the host, run
Ansible, or change Blinkt. The status daemon may contact the enrolled Host for
its lightweight health, update, and connectivity checks.

The controller installs Go 1.26.10 under
`/opt/boetticher/toolchains/go1.26.10/` and Ansible Core 2.19.11 in
`/opt/boetticher/venv/`. The Boetticher binary is always the prebuilt payload;
the Pi does not compile it. Go checks use `GOTOOLCHAIN=local`.

If log2ram was installed during this boot, bootstrap reports a failed readiness
check and asks for an explicit reboot:

```text
Controller readiness: FAIL — reboot required to activate log2ram

Next:
  sudo reboot
```

After reconnecting with a fresh key-authenticated SSH session, rerun bootstrap
and status. A successful final state reports `Controller readiness: PASS`.

With readiness passing, continue with the Host journey in
[Start here](start.html#first-host-journey). The HOME-recovery cutover
(`--home-recovery` and `host authorize-controller`) is described in
[Start here: Modules](start.html#modules).

## Verifying the Host key

Boetticher never accepts a Host key on first use. The Mac (or another machine
with an existing strict SSH relationship to the Proxmox Host) is the trust
bridge: verify the Host key there, then copy only that public key to the
Controller for `host import-host-key`. Do not use `ssh-keyscan`, TOFU, or
`StrictHostKeyChecking=no`.

From the Mac, first verify the existing relationship without accepting a new
key:

```sh
ssh -o StrictHostKeyChecking=yes root@192.168.4.5 'hostname; pveversion'
```

For an un-hashed, unambiguous entry, copy the exact Ed25519 record from the
Mac's trusted file:

```sh
awk '$1 == "192.168.4.5" && $2 == "ssh-ed25519" { print $2 " " $3; exit }' \
  ~/.ssh/known_hosts
```

If the file is hashed or has multiple ambiguous records, stop and verify the
record manually through the trusted Mac/console rather than guessing. To
authorize the Controller, inspect the Host's effective `AuthorizedKeysFile`
through the trusted Mac session and append the key printed by
`host show-public-key` idempotently to that existing root key file; do not
replace other recovery keys.

`host enroll` then performs strict read-only checks with the persistent
Controller identity and records only `/etc/boetticher/lab.yml` with the
verified address, root user, node binding, and `no-subscription` repository
policy. It does not create API tokens, application secrets, PKI, guests,
storage, or networking. The Controller keeps the private key at
`/var/lib/boetticher/controller/ssh/id_ed25519` with root-only permissions and
the imported Host key at `known_hosts` in the same directory. Independent
Mac/root access remains the recovery path.

## Status daemon and peripherals

This section is the canonical description of the Controller peripherals.
Blinkt, StreamDeck, display, and kiosk hardware are Controller implementation
details, never Module namespaces.

The Controller runs one local `boetticher-status.service` daemon. It is the
exclusive owner of the Pimoroni Blinkt and its GPIO23/GPIO24 path, and of an
attached StreamDeck. Bootstrap and Host operations send best-effort progress
events over its root-only Unix socket at `/run/boetticher/status.sock`. If the
socket or hardware is unavailable, the operation continues normally.

Controller bootstrap always installs the status daemon and its packaged
driver; the old standalone Controller StreamDeck service is removed. Blinkt and
StreamDeck are optional: if either is absent, the daemon keeps running, and the
GPIO check is reported as `NOT TESTED` rather than blocking Controller
readiness. Host apply always installs the packaged Host speedtest helper; it
does not depend on either device. Host status and apply compare the installed
helper's `--version` with the Controller release, so `host apply` reinstalls a
stale helper.

The display is a lightweight operator convenience, not authoritative
monitoring or qualification. A green LED means only that its corresponding
simple, read-only check passed. It does not depend on the observability
runtime or an external monitoring API. Unconfigured capabilities are off,
configured-but-unavailable capabilities are failed, and unknown is never
healthy. The daemon runs with root privileges in the reference image because
the GPIO device is root-owned; its systemd unit otherwise confines network,
filesystem, and device access.

### Blinkt

The fixed eight-pixel layout, viewed from the operator side, is:

```text
CTL HOST NETWORK VPN TAILNET NET CTRL-UPDATES HOST-UPDATES
```

| Display | Meaning |
| --- | --- |
| Breathing green | The lightweight check is healthy |
| Steady blue | Startup, checking, or configuration staged |
| Pulsing amber | Attention or degraded operation |
| Flashing red | A meaningful health or operation failure |
| Off | Not configured or not applicable |

- `CTL` is local Controller health and `HOST` is the enrolled Proxmox Host.
- `NETWORK` is the aggregate of the Firewall, DNS, and DHCP/NTP capabilities'
  native control-plane status. It does not run the packet-acceptance suite, so
  red means desired/provider drift or a failed local predicate, not proof of a
  network outage. The individual states are on the StreamDeck NETWORK view
  and in `module firewall|dns|dhcp status`.
- `VPN` is the integrated firewall-provider VPN status. A configured VPN with
  unverified egress is distinct from a failed or unconfigured VPN, and VPN
  availability does not prove protected-client enforcement.
- `TAILNET` is the subnet router's native local status; it does not represent
  remote packet qualification. A disconnected coordination service is
  attention while existing approved routes may continue; policy drift is
  failed.
- `NET` runs a lightweight Host-side connectivity check every 60 seconds. It
  is green when Host Internet connectivity works and the most recent hourly
  speedtest download meets the configured threshold, amber when connectivity
  works but the speedtest is below threshold or has no usable recent result,
  and red only after connectivity fails twice consecutively. The hourly
  speedtest runs on the Host using the release-built `showwin/speedtest-go`
  helper on `vmbr0`, over the existing strict SSH relationship; the reference
  threshold is 500 Mbps for an approximately 1000 Mbps service. It uses the
  external speedtest.net service only for that explicit sample.
- `CTRL-UPDATES` is green when no Controller updates are available, amber when
  updates or the native `/var/run/reboot-required` marker need attention, and
  blue while a Boetticher configuration-staged event is active.
  `HOST-UPDATES` is green when no Proxmox package updates or Host reboot are
  reported, and amber when either is. Both read existing local/cached APT state
  only; they never install packages, refresh package lists, or reboot.

Apply and test commands temporarily use dedicated operation modes. Apply shows
the blue Knight Rider chase while it runs, then holds an all-green or all-red
result briefly. Test shows one pixel per named test group: active tests pulse
blue, passed tests are solid green, and failed tests are solid red. The
firewall test uses five groups (gateway, Internet egress, inter-zone policy,
HOME protection, and administration). The final result is held briefly before
standard status resumes. Display notifications never affect the command
result.

### StreamDeck

The 15-key StreamDeck is a detailed, read-only view of the enrolled Host. The
home screen rows are:

```text
PVE      CPU      RAM      DATA     NET
guest    guest    guest    guest    guest
NETWORK  VPN      TAILNET  SCROLL   REFRESH
```

`PVE` shows the Host (or the step of a running operation); `DATA` follows
fresh/stale Host telemetry; `NET` shows the latest hourly throughput. The
middle row shows five VM/LXC guests sorted by VMID; each tile shows `VM<id>` or
`CT<id>`, the hostname, and its runtime status, and `SCROLL` pages through
guests five at a time. `NETWORK`, `VPN`, and `TAILNET` open their detail
views; the VPN and Tailnet views show the capability state and its reported
reason.

The Host detail view shows node, Proxmox version, uptime, CPU, RAM, DATA, Host
updates, reboot-required state, and the `FW`, `DHCP`, `VPN`, `TAILNET`, and
`DNS` capability states. The guest detail view shows identity, name, type,
CPU, RAM, and uptime. Every detail view has BACK and REFRESH. Apart from the
bounded `ST-LAB` speedtest below, StreamDeck input cannot start, stop, reboot,
deploy, or run shell commands.

The NETWORK detail view uses this layout:

```text
NETWORK  FIREWALL  DNS     DHCP/NTP  DETAIL
ST-LAB   ST-VPN    PING    DOWN      UP
SERVER   -         -       BACK      REFRESH
```

`ST-LAB` runs one manual speedtest from inside the LAB through the firewall's
ordinary WAN egress. The Host helper creates a temporary owned namespace
(`bt4s-lab`, host veth `bt4s-lab-h`) as an access port on exactly the SERVERS
VLAN (untagged, PVID, with the bridge default VLAN 1 removed) with an address
from the reserved `.250-.254` probe space, which is outside the VPN-protected
`.224/28` range, and resolves names through the SERVERS gateway like any LAB
client. It streams one progress line per phase over the strict Host SSH
transport. While the test runs the key is blue and shows the phase or the live
download/upload rate; PING, DOWN, UP, and SERVER show the split figures. The
finished result stays on the keys, with its completion time, until the next
run, including after navigating away; a failure shows `FAILED` and the reason
scrolls on SERVER. A second press while running shows `BUSY`; a press during
the hourly NET sample shows `HOURLY`, and with no firewall configured shows
`NO FW`. The hourly sample waits while a manual run is active, manual results
never feed the NET/Blinkt throughput figure, and the helper shares the
firewall packet-test lock so the two never run together. Each run removes its
fixture with a fresh cleanup budget, removes an owned leftover from an
interrupted run before starting (reported on SERVER), and reports a cleanup
failure as a failed run. Ownership is proven by the reserved namespace and a
host veth whose peer is that namespace's `eth0`; a leftover at any point of
setup (not yet on vmbr1, still carrying VLAN 1) is recognised, while another
bridge, another VLAN, a non-SERVERS address, or a same-named foreign link is
refused and left in place. Recovery without starting a test uses the existing
native cleanup surface, which also needs no healthy firewall provider:

```text
sudo boetticher module firewall test --cleanup-only --yes
```

`ST-VPN` shows `N/A`. VPN egress is selected only for declared VPN client
reservations in the protected range, enforced by the firewall's source rules
and VPN client set, so an honest VPN-path test needs a declared probe client
rather than a temporary one.

### Status configuration

The optional `status` section of `/etc/boetticher/controller.yml` keeps these
defaults explicit without adding a status database or generated state:

```yaml
status:
  interval: 30s
  ping_interval: 60s
  internet:
    throughput_interval: 1h
    healthy_mbps: 500
  blinkt:
    enabled: true
    brightness: 0.3
  streamdeck:
    enabled: true
    brightness: 0.5
    telemetry_interval: 15s
```

## Lab snapshot portal

Controller bootstrap also installs the lab snapshot portal
(`boetticher-labviewer.service`) and its five-minute refresh timer
(`boetticher-lab-snapshot.timer`). The viewer listens on the Controller's
SERVERS address (`10.10.20.10:8090`) and serves a human page at `/lab/`,
machine data at `/lab/snapshot.json`, and the packaged Start, Lab, and Modules
pages at `/lab/docs/`. When the observability runtime is applied, its Caddy
frontend publishes the portal as `lab.<public domain>` and
`labviewer.<public domain>`, and the managed firewall admits only that runtime
to the portal port.

The snapshot contains redacted desired intent, allowlisted live facts, source
timestamps, explicit unknown/stale states, and links. It never publishes
credentials, private keys, raw configuration, or arbitrary logs. Holmes reads
the same bounded publication instead of receiving SSH or Proxmox credentials.
The unit reads `/etc/boetticher/lab.yml` and the packaged docs read-only and
writes only `/var/lib/boetticher/labviewer/snapshot`. See
[labviewer/README.md](https://github.com/gofastercloud/boetticher/blob/main/labviewer/README.md)
for running it locally and for optional `control_surfaces` links.

## Restricted agent access (`agent-lab`)

Autonomous agents on a Mac can inspect the Controller and lab without touching
the operator's Secretive master keys. The Mac-side `agent-lab` binary connects
over a dedicated, non-interactive SSH key to the local `boetticher-agent`
account on the Pi, where OpenSSH forces every session through
`/usr/local/libexec/boetticher-agent-broker`. The broker parses
`SSH_ORIGINAL_COMMAND` without a shell, enforces a strict allowlist and policy,
and executes `/usr/local/bin/boetticher` directly via `execve`.

`boetticher-agent-broker` is packaged in the Controller release and installed
by `install.sh`. On the Mac, build `bin/agent-lab` with `make build`.

### Generate the Mac agent key and pin the Controller host key

Generate the dedicated Ed25519 identity on the Mac (stored with `0600`
permissions at `~/.config/groundhog/agent_lab_ed25519` by default):

```sh
agent-lab init
```

`agent-lab init` prints the public key and the exact enable command for the Pi.
Next, create `~/.config/groundhog/agent-lab.yml` (overridable via `--config` or
`AGENT_LAB_CONFIG`; unknown YAML fields are rejected):

```yaml
host: 192.168.4.10
user: boetticher-agent
port: 22
identity_file: ~/.config/groundhog/agent_lab_ed25519
known_hosts_file: ~/.config/groundhog/agent_lab_known_hosts
```

Only `host` is required; the other fields default to the values shown above.
Pin the Pi's verified SSH host key from the Mac's existing trusted
`~/.ssh/known_hosts` into `~/.config/groundhog/agent_lab_known_hosts` without
using `ssh-keyscan`, TOFU, or `StrictHostKeyChecking=no`:

```sh
awk '$1 == "192.168.4.10" && $2 == "ssh-ed25519" { print; exit }' \
  ~/.ssh/known_hosts > ~/.config/groundhog/agent_lab_known_hosts
```

`agent-lab` fails closed if `known_hosts_file` is absent or if `identity_file`
grants group or other permissions. It runs `ssh` with `-F /dev/null`,
`IdentitiesOnly=yes`, `StrictHostKeyChecking=yes`, `BatchMode=yes`, and
`SSH_AUTH_SOCK` stripped from the environment so it never contacts Secretive or
an ambient `ssh-agent`.

### Enable access on the Pi and verify

Connect to the Pi over your normal Secretive-backed operator SSH session.
Preview the local changes first with `--plan`, then apply with `--yes`:

```sh
sudo boetticher controller agent-access enable \
  --key 'ssh-ed25519 AAAA... boetticher-agent' \
  --plan
sudo boetticher controller agent-access enable \
  --key 'ssh-ed25519 AAAA... boetticher-agent' \
  --yes
```

`enable --yes` creates the locked-password `boetticher-agent` system user if
absent, atomically writes `0600` `~boetticher-agent/.ssh/authorized_keys` with
`restrict,command="/usr/local/libexec/boetticher-agent-broker"`, atomically
writes a `visudo`-validated `0440` rule at
`/etc/sudoers.d/boetticher-agent-broker`, and creates the default read-only
`/etc/boetticher/agent-policy.yml` (`0644`) only if it does not already exist.
Only single-line `ed25519`, `ecdsa`, and `rsa` keys without embedded
`authorized_keys` options are accepted.

Inspect the configured state on the Pi (prints key type, SHA256 fingerprint,
and comment—never raw key material):

```sh
sudo boetticher controller agent-access status
```

Then verify from the Mac without touching Secretive:

```sh
agent-lab status
```

`agent-lab status` runs `boetticher controller status`. Pass any other allowed
subcommand directly, for example `agent-lab host status --details` or
`agent-lab module firewall status`.

### Tiers, policy, and hard denials

By default (and whenever `/etc/boetticher/agent-policy.yml` is absent), the
broker permits only **Tier 1** read-only commands:

- `controller status [--operator USER]`
- `host status [--details]`, `host plan-storage`, `host list-systems`,
  `host system-status <name>`, `host upgrade --plan`, and
  `host reboot --plan [--with-guests]`
- `module <capability> status` for `firewall`, `dns`, `dhcp`, `observability`,
  `logging`, `monitoring`, `statuspage`, `vpn` (`--details` permitted),
  `tailnet`, and `media`
- `module <capability> plan` for `firewall`, `dns`, `dhcp`, `observability`,
  `vpn`, `tailnet`, and `media`
- `module dns list-records`, `module dhcp list-reservations`, and
  `module dhcp list-leases [--details]`
- `module logging query` with bounded flags (`--host`, `--unit`, `--level`,
  `--since` up to `168h`, `--limit` `1`–`500`)
- `module monitoring incidents list [--json]` and
  `module monitoring incidents show <id> [--json]`

To opt into **Tier 2** active-test or mutation capabilities, edit the
root-owned `/etc/boetticher/agent-policy.yml` on the Pi. The broker rejects
symlinks, non-regular files, non-root ownership, group/world-writable modes,
and unknown YAML fields:

```yaml
tier2:
  system_power: false       # host start-system|stop-system <name> --plan|--yes
  firewall_test: false      # module firewall test --plan|--yes
  dns_records: false        # module dns add-record|remove-record
  dhcp_reservations: false  # module dhcp add-reservation|remove-reservation
  module_apply: []          # subset of: firewall, dns, dhcp, observability, vpn, tailnet, media
```

The following are **always hard-denied** and cannot be enabled by policy:

- Any `teardown` or `secrets` subcommand, or any argument referencing
  `install.sh`
- `controller reboot`, `controller bootstrap`, and `controller agent-access`
- `host reboot --yes` (only `--plan` is allowed)
- Sensitive flags: `--data-disk`, `--api-key-stdin`, `--auth-key-file`,
  `--cloudflare-token-file`, and `--credentials-file`

### Audit logs and instant revocation

Every broker invocation writes a structured JSON audit record (`timestamp`,
`user`, `key_comment`, `argv`, `decision`, `tier`, `reason`, `exit_code`, and
`duration_ms`) to `stderr`, and SSH/sudo activity for `boetticher-agent` is
recorded in `journald` on the Controller:

```sh
sudo journalctl -u ssh -t sudo --since '1 hour ago' | grep boetticher-agent
```

When the observability module is enabled, Controller `journald` logs are
shipped to VictoriaLogs and can be queried via:

```sh
boetticher module logging query --unit ssh --since 1h --limit 100
```

To revoke agent access immediately from a Secretive operator session on the Pi:

```sh
sudo boetticher controller agent-access disable --yes
```

Use `--plan` first to preview removals. `disable --yes` removes
`~boetticher-agent/.ssh/authorized_keys` and
`/etc/sudoers.d/boetticher-agent-broker` immediately while preserving
`/etc/boetticher/agent-policy.yml`; pass `--purge-policy` to delete the policy
file as well.

## Installed paths and maintenance

| Path | Purpose |
| --- | --- |
| `/opt/boetticher/releases/<build-id>/` | Immutable installed payload |
| `/opt/boetticher/current` | Active release symlink |
| `/opt/boetticher/venv/` | Private Ansible environment |
| `/opt/boetticher/toolchains/go1.26.10/` | Pinned Go toolchain |
| `/usr/local/libexec/boetticher-agent-broker` | Forced-command SSH broker for restricted agent access |
| `/etc/boetticher/controller.yml` | Controller-local operator and status settings |
| `/etc/boetticher/agent-policy.yml` | Root-owned opt-in Tier 2 policy for restricted agent access |
| `/etc/boetticher/lab.yml` | Host, LAB, and capability intent |
| `/etc/sudoers.d/boetticher-agent-broker` | Narrow NOPASSWD rule for `boetticher-agent` |
| `/var/lib/boetticher/controller/` | Controller state, SSH identity, and the log2ram boot marker |
| `/var/lib/boetticher/labviewer/` | Lab snapshot facts and publication |
| `/run/boetticher/status.sock` | Root-only best-effort operation event socket |
| `/var/cache/boetticher/` | Downloaded package/toolchain cache |
| `/var/log/boetticher/bootstrap.log` | Bounded bootstrap output |
| `/var/log/boetticher/operations.log` | Bounded underlying host-operation output |

The playbook enables Debian security-only unattended upgrades and APT timers,
without automatic reboot or automatic Boetticher/Go/Ansible upgrades. It keeps
journald at 32 MiB persistent and 16 MiB runtime limits, and rotates bootstrap
logs daily for seven files.

log2ram uses the signed Azlux Trixie repository with its pinned public key and a
128 MiB RAM-backed `/var/log`. It is not a backup: logs not synchronized before
a sudden power loss can be lost. The native log2ram service and synchronization
timer remain responsible for persistence; bootstrap never forces a live
unmount or reboot.

Reboot the Controller explicitly; it never reboots the Host:

```sh
sudo boetticher controller reboot --yes
```

Host upgrades and reboots are covered in
[Start here: Host maintenance](start.html#host-maintenance).

## Pinned inputs

The pinned inputs are [Raspberry Pi OS](https://www.raspberrypi.com/documentation/computers/os.html)
Debian 13/Trixie ARM64, [Go 1.26.10](https://go.dev/dl/),
[Ansible Core 2.19.11](https://pypi.org/project/ansible-core/2.19.11/), and
[Azlux log2ram](https://github.com/azlux/log2ram). The Go archive checksum and
Ansible pin are recorded in the repository; the Azlux archive key is shipped as
a public runtime asset. No alternate workstation, TUI, kiosk, or external
Companion bootstrap path is supported.
