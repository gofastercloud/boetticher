# DHCP, DNS, and NTP

In managed mode, Kea DHCPv4 and Kea D2 run on `lab-fw-01`. In external mode,
DHCP is the operator appliance's responsibility. Both modes retain the same
fixed zones and gateway addresses.

TRUSTED, SERVERS, and MGMT receive `10.10.20.10` and `10.10.20.11` for DNS and
NTP. SANDBOX receives `10.10.50.1` for both, keeping it independent of the
SERVERS guests. The DNS guests run PowerDNS Authoritative and Chrony with
Blocky as the default client-facing recursive/filtering provider. AdGuard Home
is a supported typed alternative. PowerDNS receives authenticated Kea D2
RFC2136 updates.

MGMT has reservations only. Core guests use fixed model addresses and do not
depend on DHCP for their own operation.
