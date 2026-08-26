# TRUSTED clients

TRUSTED is VLAN 10, `10.10.10.0/24`, gateway `10.10.10.1`. DHCP supplies the
two AdGuard resolver addresses and the two DNS/NTP service addresses. Use
reservations for devices that need stable addresses. Access to internal
services and administration remains governed by the explicit gateway policy.
