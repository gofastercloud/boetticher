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

Proxmox performs VLAN classification by attaching separate firewall vNICs to
`vmbr1` with tags 10, 20, 50, and 99. The firewall sees ordinary interfaces
named `wan0`, `trusted0`, `servers0`, `sandbox0`, and `mgmt0`; it does not see a
trunk and does not create VLAN subinterfaces. Proxmox is already trusted to
attach guests to the right bridge and VLAN. A compromised hypervisor can bypass
guest firewall guarantees.

Forwarding is disabled while the gateway is being prepared. boetticher renders
one namespaced ruleset, validates it with `nft -c`, retains the previous known-
good file, applies the replacement transactionally, and enables IPv4 forwarding
only after the policy and services are ready. IPv6 forwarding is disabled in
v0.3.

SANDBOX may use the gateway for DHCP, public DNS, and NTP, but cannot reach the
TRUSTED, SERVERS, or MGMT networks. The deny rules precede Internet egress.
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
static generated documentation; live state belongs in Zabbix.

The platform is IPv4-only in v0.3. Dynamic DHCP DNS registration publishes a
lease-derived name; it never makes that workload boetticher-managed.

## Core and module boundary

Core is the only privileged mutation boundary. Built-in modules are trusted
compiled-in boetticher code, but they emit bounded declarations for guests,
network intent, DNS, certificates, monitoring, backups, and portal metadata.
They do not call Proxmox, nftables, SOPS/Age, CA signing, Zabbix, or arbitrary
host-shell mutation paths directly. Core resolves dependencies, capabilities,
fixed identities, ownership, and conflicts before deployment.

Official appliance artifacts derive from pinned Debian 13 definitions and are
checksum-verified before use. The appliance root filesystem is replaceable;
module-declared databases, lease state, and SSH host identity are persistent.
Site configuration, policy, certificates, and runtime configuration are
deployment-derived.

Systemd credentials are the standard service-secret delivery mechanism. Kea
receives a credential through a protected ephemeral secret file. PowerDNS may
persist its TSIG material in its protected supported backend because its
operating model requires that datastore. SOPS/Age remains the controller-side
recovery authority in both cases. Proxmox/root remains a trusted host boundary.

Application services run as dedicated non-root users wherever their software
allows it. A compromised module process is not granted controller identity,
SOPS/Age authority, CA signing keys, or another module's ownership. A root
compromise inside a guest remains bounded by the trusted Proxmox and network
boundaries described above.

Malformed configuration, duplicate DNS identities, fixed VMID collisions,
conflicting network declarations, artifact checksum mismatches, missing
gateway capability, dependency cycles, and secret values in declarations are
rejected before infrastructure mutation.
