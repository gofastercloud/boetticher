# SANDBOX

SANDBOX uses VLAN 50 and `10.10.50.0/24` in V1. Clients use OPNsense for DNS, NTP, and gateway. The routed policy denies SANDBOX access to TRUSTED, SERVERS, and MGMT while allowing Internet egress.

The possible `/32` client-address experiment would use DHCP option 121 to install an on-link gateway route and a default route. It must be tested independently on Windows 11, macOS, iOS, Linux/systemd-networkd, NetworkManager, and Android before being enabled. It is defense in depth only: a client can change its routes, and shared Ethernet peers can still communicate at L2 unless the Proxmox or switch enforcement mechanism blocks them.

The security claim is therefore explicit: OPNsense provides inter-zone isolation; the Proxmox firewall can provide virtual SANDBOX east-west isolation; managed-switch client/port isolation is required for physical SANDBOX peers.
