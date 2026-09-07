---
layout: default
title: Client services
section: networking
description: Phase 4B DHCP, local naming, encrypted DNS, and client-facing time.
---

# Client services

Phase 4B adds two peer capabilities to the existing OpenWrt firewall
appliance:

```text
module firewall apply
module dns apply
module dhcp apply
```

DNS and DHCP share one typed intent in `/etc/boetticher/lab.yml`, one verified
HTTPS/ubus management connection, one appliance mutation lock, and one
coordinated dnsmasq configuration. NTP is supporting behaviour of DHCP/DNS,
not a standalone capability.

## Reference scopes

| Zone | VLAN | Policy | Pool |
| --- | ---: | --- | --- |
| TRANSIT | 5 | reservations only | none |
| INFRA | 10 | reservations only | none |
| SERVERS | 20 | pool plus reservations | `.100-.199` |
| TRUSTED | 30 | pool plus reservations | `.100-.199` |
| SANDBOX | 40 | pool plus reservations | `.100-.199` |
| MGMT | 99 | reservations only | none |

The gateway remains `.1`; `.200-.254` is reserved expansion space and the
`.250-.254` range is excluded from normal pools for the temporary probe
fixtures. The default lease is 12 hours. Reservations use a stable MAC and
the canonical name `<name>.lab.home.arpa`; changing/private client MACs must
be made stable before a reservation can match.

HOME is outside LAB DHCP. Boetticher never replaces HOME DHCP, adds a HOME
route, or gives a managed guest a second management NIC.

## Supported commands

```text
boetticher module dns plan
boetticher module dns apply [--yes]
boetticher module dns status
boetticher module dns teardown --plan
boetticher module dns teardown [--yes]
boetticher module dns add-record NAME --type A|CNAME --value VALUE [--yes]
boetticher module dns remove-record NAME [--yes]
boetticher module dns list-records

boetticher module dhcp plan
boetticher module dhcp apply [--yes]
boetticher module dhcp status
boetticher module dhcp teardown --plan
boetticher module dhcp teardown [--yes]
boetticher module dhcp add-reservation NAME --zone ZONE --mac MAC --address IPv4 [--yes]
boetticher module dhcp remove-reservation NAME [--yes]
boetticher module dhcp list-reservations
boetticher module dhcp list-leases
```

Resource additions are desired-state mutations and reconcile immediately.
Identical definitions are no-ops; conflicting definitions fail before any
write. A failed provider application retains the saved intent and reports the
ordinary recovery command.

`list-reservations` reads saved intent. `list-leases` reads the native
persistent dnsmasq lease file and never synthesises runtime leases from
reservations. Removing a reservation does not revoke an already-issued lease;
the native lease expires or is released normally.

## DNS and time

Clients use the firewall gateway for DNS, the local domain and DHCP option 42
NTP. Public queries go from dnsmasq to Stubby and then to Quad9 over verified
DNS-over-TLS at `9.9.9.9:853` and `149.112.112.112:853` using the TLS identity
`dns.quad9.net`, with ECS disabled and no plaintext fallback. Local names and
private reverse answers remain local; unknown local names are not forwarded.

The appliance keeps upstream time acquisition independent of whether
client-facing DHCP/NTP is enabled. LAB clients inherit the firewall's time
server when DHCP is enabled. Proxmox LXCs inherit the Host realtime clock and
are not given `CAP_SYS_TIME`; Controller and Host recovery time configuration
is outside this capability.

## Teardown and status

DHCP teardown disables DHCP and client-facing NTP but retains reservation
intent and the shared appliance. DNS teardown refuses while DHCP is enabled
and retains record intent. Firewall teardown refuses while either dependent
capability is enabled. Repeated teardown is an already-disabled/no-change
success.

Status is observational. Not configured is off, configured and unavailable is
failed, and only bounded native service/configuration readback is healthy.
Status never applies configuration or runs the acceptance suite.

## Tests and limitations

`module dhcp test --plan` and `module dns test --plan` are read-only. Approved
tests use one temporary VLAN namespace per zone, an exact veth/access port,
bounded cleanup, and a real DHCP client. They verify allocation, gateway,
DNS/domain/NTP options, reservation-only positive controls, local resolver
answers, and encrypted recursive resolution. Failed transport, fixture setup,
dead targets, malformed helper output, and missing positive controls are not
successful denials.

The test does not claim DHCPv6, IPv6 policy, mDNS reflection, PXE/TFTP, DHCP
relay, DoH/HTTPS bypass prevention, physical switch isolation, or Wi-Fi
isolation. DHCP option adoption remains client/OS-specific and may require a
renewal or stable per-network client identity.
