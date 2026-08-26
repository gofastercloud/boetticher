# Architecture

Lab-in-a-Box is a fixed four-zone IPv4 platform: TRUSTED (`10.10.10.0/24`, VLAN 10), SERVERS (`10.10.20.0/24`, VLAN 20), SANDBOX (`10.10.50.0/24`, VLAN 50), and MGMT (`10.10.99.0/24`, VLAN 99).

OPNsense owns routing, NAT, inter-zone firewalling, DHCP, SANDBOX DNS/NTP, and aliases. Proxmox does not route between VLANs. `vmbr1` starts as a virtual-only VLAN-aware bridge and may later receive a physical tagged trunk.

The foundation is Proxmox, OPNsense, two DNS/NTP nodes, Zabbix, and the passive generated portal. The canonical model drives all platform projections.
