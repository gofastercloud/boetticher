# DHCP, DNS, and NTP

In managed mode, Kea DHCPv4 and Kea D2 run on `lab-fw-01`. In external mode,
DHCP is the operator appliance's responsibility. Both modes retain the same
fixed zones and gateway addresses.

TRUSTED and SANDBOX receive DHCP service and authenticated DDNS updates.
TRUSTED uses `10.10.10.10` and `10.10.10.11` for DNS and NTP; SANDBOX receives
`10.10.40.1` for both, keeping it independent of the INFRA guests. TRANSIT,
INFRA, SERVERS, and MGMT are static-only zones and do not receive DHCP scopes
or DDNS updates. The DNS guests run PowerDNS Authoritative and Chrony with
Blocky as the default client-facing recursive/filtering provider. AdGuard Home
is a supported typed alternative. PowerDNS receives authenticated Kea D2
RFC2136 updates from TRUSTED and SANDBOX only.

Core guests in TRANSIT, INFRA, SERVERS, and MGMT use fixed model addresses and
do not depend on DHCP for their own operation.
