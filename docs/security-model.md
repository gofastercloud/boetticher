# Security model

boetticher is a fun, opinionated pre-alpha project. Its security model is
explicit and testable, but it is not an audited production appliance.

## Managed gateway

In managed mode, `lab-fw-01` is a small Debian QEMU/KVM VM with its own guest
kernel. It runs nftables, Kea, and the small services needed by SANDBOX. It is
the inter-zone routing and filtering boundary. The default input and forward
policies are drop; stateful established/related traffic and documented service
paths are allowed explicitly. Internal traffic is not NATed. Intended internal
networks are masqueraded only when leaving `wan0`.

Diagnostic IPv4 echo requests from internal non-TRANSIT zones to the managed
gateway are allowed. WAN-sourced ICMP and inter-zone ICMP remain denied unless
an explicit policy path permits them.

Proxmox performs VLAN classification by attaching separate firewall vNICs to
`vmbr1` with tags 5, 10, 20, 30, 40, and 99. The firewall sees ordinary interfaces
named `wan0`, `transit0`, `infra0`, `servers0`, `trusted0`, `sandbox0`, and
`mgmt0`; it does not see a
trunk and does not create VLAN subinterfaces. Proxmox is already trusted to
attach guests to the right bridge and VLAN. A compromised hypervisor can bypass
guest firewall guarantees.

Forwarding is disabled while the gateway is being prepared. boetticher renders
one namespaced ruleset, validates it with `nft -c`, retains the previous known-
good file, applies the replacement transactionally, and enables IPv4 forwarding
only after the policy and services are ready. IPv6 forwarding is disabled in
v0.3.

SANDBOX may use the gateway for DHCP, public DNS, and NTP, but cannot reach the
TRUSTED, SERVERS, INFRA, or MGMT networks. The deny rules precede Internet
egress. TRUSTED and SANDBOX use dynamic DHCP plus DDNS; SERVERS uses
reservation-only DHCP plus DDNS. TRANSIT, INFRA, and MGMT are static-only.
MGMT is intentionally small and administrative; it is not a general
"important servers" VLAN.

## External gateway

External mode is bring-your-own-firewall. boetticher owns the Proxmox-side
trunk and publishes the fixed VLAN, gateway, DHCP, DNS, NTP, and policy intent,
but does not manage or inspect the appliance's internal configuration. The
operator's appliance is trusted to implement the contract. boetticher can
perform observable black-box checks, not prove the appliance's hidden rule
ordering.

## Other boundaries

The controller is separate from Proxmox. SOPS encrypts platform secrets and
the Age private identity stays outside Git. CA private keys remain controller-
side; endpoint private keys are generated on managed hosts where practical.
The Proxmox SSH bastion is the normal path to internal hosts. The portal is
static generated documentation; live monitoring state belongs in Pulse.

The platform is IPv4-only in v0.3. Dynamic DHCP DNS registration publishes a
lease-derived name; it never makes that workload boetticher-managed.

## Core and module boundary

Core is the only privileged mutation boundary. Built-in modules are trusted
compiled-in boetticher code that emits bounded declarations for guests,
network intent, DNS, certificates, monitoring, backups, and portal metadata.
Core resolves dependencies, capabilities, fixed identities, ownership, and
conflicts before deployment. Modules do not call Proxmox, nftables, SOPS/Age,
CA signing, Pulse, or arbitrary host-shell mutation paths directly.

Appliance definitions are deterministic and derive from pinned Debian 13
inputs. Concrete artifact bytes are independently SHA-256 verified before
use; build smoke tests and the Trivy policy must pass. Package manifests,
SBOMs, scanner reports, and builder metadata are useful release/debug outputs,
not separate trust authorities. Appliance root filesystems are replaceable;
module-declared databases, lease state, and SSH host identity are persistent.
Site configuration, policy, certificates, and runtime configuration are
deployment-derived.

Modules request durable volumes but cannot claim disks or create storage
topology. Systemd credentials are the standard service-secret delivery
mechanism. Kea receives a credential through a protected ephemeral secret
file. PowerDNS may persist TSIG material in its protected supported backend
because its operating model requires that datastore. SOPS/Age remains the
controller-side recovery authority, and endpoint private keys remain
endpoint-local where designed.

Application services run as dedicated non-root users wherever their software
allows it. A compromised module process is not granted controller identity,
SOPS/Age authority, CA signing keys, or another module's ownership. Proxmox
and host root remain trusted boundaries.

## Privilege lifecycle

Bootstrap uses the supplied initial administrator path to establish platform
identities, host configuration, and the scoped Proxmox API token. It installs
the operator key for a temporary root SSH deployment window on the Proxmox
host and managed guests. Ansible connects through that root transport with
`become: false`; it does not use a durable sudo rule for `labadmin`.

The durable `labadmin` identity has an unprivileged shell on Proxmox and
appliances and no general sudo authority. The managed firewall retains only
fixed, read-only inspection helpers for status, nftables observation, leases,
and bounded kernel logs. Proxmox lifecycle operations use the scoped
`BoetticherProvisioner` API token. Runtime configuration and credential
installation are fixed Core operations over the temporary root transport.

After successful convergence, Core removes the temporary root authorized key
from every managed guest and the Proxmox host, removes the host's temporary
root SSH allowance, and locks the root password. If deployment stops before cleanup,
the temporary root window remains available for a safe retry. Cleanup failure
is a deployment hold; recovery uses the authenticated root/bootstrap path to
complete cleanup. Operator break-glass root access is separate recovery
authority and is not represented as durable `labadmin` privilege. The
ephemeral builder uses the temporary root deployment key and is destroyed by
bootstrap cleanup.

Central logging uses bounded local journald and asynchronous HTTPS/mTLS upload
to a mandatory journal collector. The collector is a secondary operational log
copy, not an availability dependency or cryptographic non-repudiation system.

Pulse uses a dedicated read/audit-oriented Proxmox API identity for inventory,
guest, storage, and backup state. A separate `agent:report` token is delivered
to the Pulse host agent through an encrypted systemd credential. The generic
`monitoring-agent` tag selects agent targets; `lab-proxmox-01` is the default
target, and VM/LXC guests do not receive an agent. The monitor UI retains the
HTTPS/mTLS boundary, while the supported token-authenticated agent routes carry
host reports without a client certificate.

The managed gateway permits only `lab-monitor-01` to reach the Proxmox API on
TCP/8006. This is the explicit network intent required for Pulse inventory and
does not grant general INFRA-to-MGMT access.

If a later deployment needs to modify an already-converged guest, Core may
re-arm that same temporary key through the authenticated Proxmox host boundary
for the exact owned guest, and removes it again after convergence.

The DNS module is mandatory. Blocky is the default recursive/filtering
implementation and AdGuard is a typed alternative; PowerDNS remains
authoritative in both modes, and internal negative answers never leak to public
upstreams. Malformed configuration, duplicate DNS identities, fixed VMID
collisions, conflicting network declarations, artifact checksum mismatches,
missing gateway capability, dependency cycles, and secret values in
declarations are rejected before infrastructure mutation.
