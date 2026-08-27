# Switch configuration

The optional second Proxmox NIC connects to a managed switch as an 802.1Q
trunk. Allow VLANs 5, 10, 20, 50, and 99. Use access ports for ordinary physical
clients and place them in the intended zone. Enable client/port isolation for
physical SANDBOX peers where the switch supports it.

In managed gateway mode, Proxmox tags the firewall VM's five zone vNICs. In
external mode, the physical trunk carries the five VLANs to the operator-owned
firewall, which supplies the `.1` gateway for each network. TRANSIT is VLAN 5,
a permanent Core routing/security-edge interface, and is not created or removed
by an individual module. Do not make the
HOME/upstream port part of this trunk.
