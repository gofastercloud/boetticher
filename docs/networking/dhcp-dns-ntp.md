# DHCP, DNS, and NTP

OPNsense Kea is the V1 DHCP authority. Its desired subnets, options, reservations, and service reconfiguration are generated from the model and applied through the supported API path.

| Zone | Allocation | DNS | NTP | Gateway |
| --- | --- | --- | --- | --- |
| TRUSTED | dynamic plus reservations | `10.10.20.10`, `10.10.20.11` | `10.10.20.10`, `10.10.20.11` | `.1` |
| SERVERS | dynamic plus reservations | `10.10.20.10`, `10.10.20.11` | `10.10.20.10`, `10.10.20.11` | `.1` |
| SANDBOX | dynamic | `10.10.50.1` | `10.10.50.1` | `.1` |
| MGMT | reservations only | `10.10.20.10`, `10.10.20.11` | `10.10.20.10`, `10.10.20.11` | `.1` |

MGMT has no pool for unknown clients. Core infrastructure uses fixed addresses owned by the model and does not depend on DHCP. Ordinary zones use the normal default gateway option; option 121 is reserved for a future classless-route experiment such as the SANDBOX `/32` spike.

`lab-dns-01` and `lab-dns-02` run AdGuard Home and Chrony independently. They are not application-state primary/secondary replicas. SANDBOX uses OPNsense for public DNS/NTP and does not receive the internal resolver addresses.
