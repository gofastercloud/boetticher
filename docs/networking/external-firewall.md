# External firewall mode

External mode is the bring-your-own-firewall option. boetticher configures the
Proxmox-side trunk and the rest of the platform, but does not configure,
authenticate to, monitor internally, back up, or recover the operator's
firewall appliance.

## Generic contract

The appliance must receive an 802.1Q trunk containing:

| VLAN | Zone | Network | Gateway |
| ---: | --- | --- | --- |
| 5 | TRANSIT | `10.10.5.0/24` | `10.10.5.1` |
| 10 | INFRA | `10.10.10.0/24` | `10.10.10.1` |
| 20 | SERVERS | `10.10.20.0/24` | `10.10.20.1` |
| 30 | TRUSTED | `10.10.30.0/24` | `10.10.30.1` |
| 40 | SANDBOX | `10.10.40.0/24` | `10.10.40.1` |
| 99 | MGMT | `10.10.99.0/24` | `10.10.99.1` |

It must route these networks, provide upstream access and source NAT as needed,
and implement the policy shown by `boetticher firewall show` and
`generated/network/external-firewall-contract.md`. The appliance owns `.1` in
all six subnets. DHCP and DDNS are required only for TRUSTED and SANDBOX;
TRANSIT, INFRA, SERVERS, and MGMT use static assignments only. SANDBOX must use
its gateway for public DNS/NTP without being given the broad internal
namespace. Proxmox uses `10.10.99.250` on MGMT.

For dynamic DNS, the external DHCP service may send authenticated RFC2136
updates to `10.10.10.10:5353`. Use the generated TRUSTED and SANDBOX child
forward zones and their two matching reverse zones, the TSIG key names in the
generated DNS projection, and HMAC-SHA256. Updates must be accepted only from
the intended DHCP/DDNS source. This is optional; a missing external DDNS setup
does not stop the rest of boetticher working.

These snippets are starting points rather than complete configurations. They
have not been exercised as part of the boetticher test suite, so check syntax
and defaults against the version of your firewall before applying them.

External mode requires an explicitly selected physical trunk before bootstrap,
including when preflight discovers exactly one eligible NIC. Bootstrap does
not silently select a candidate. Managed mode remains virtual-only unless the
operator explicitly attaches a selected trunk later.

## OPNsense example

On an OPNsense appliance, create VLAN interfaces 5, 10, 20, 30, 40, and 99 on
the physical trunk, assign the six `.1` addresses, and create DHCP scopes only
for TRUSTED and SANDBOX matching the table above. Put the generated policy into
the firewall rules for each interface and configure RFC2136/TSIG under the DHCP/DDNS features if your
version supports the required update contract. This is an orientation example,
not a supported boetticher backend.

## MikroTik RouterOS example

Create a VLAN interface for each fixed ID on the trunk-facing port, assign the
six gateway addresses, and attach DHCP servers/scopes only to TRUSTED and
SANDBOX. Place
the generated inter-zone policy in the forward chain before the Internet
accept/NAT rules. Configure DHCP client naming and RFC2136 updates only if the
RouterOS version can meet the published TSIG contract.

## OpenWrt example

Define the six bridge VLANs on the trunk port, create one logical interface per
zone with its `.1` address, and attach DHCP scopes only to TRUSTED and SANDBOX.
Put the generated policy in the zone forwarding rules and keep SANDBOX DNS/NTP
local to its gateway. Add
RFC2136/TSIG only through an OpenWrt package and configuration that has been
checked against the installed release.

boetticher does not manage any of these appliances. Remove the external setup
by reversing the appliance's own VLAN, DHCP, firewall, NAT, and DDNS changes;
boetticher's generated contract can then be regenerated or the site recreated.
