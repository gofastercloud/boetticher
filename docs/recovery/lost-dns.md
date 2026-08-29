# Lost DNS

Rebuild the failed DNS node from the site repository and its independent deployment inputs. Keep both fixed DNS/NTP addresses configured for clients. Run `boetticher deploy`, then query each fixed DNS address directly from a trusted client (for example, with `dig`) and confirm the expected authoritative and recursive results before treating service redundancy as restored. `boetticher status --live` checks managed-gateway DHCP/DDNS evidence; it does not independently probe DNS nodes.

If both nodes are unavailable, use the [main recovery runbook](recovery.md) and the [DNS module guide](../modules/dns.md); do not hand-edit PowerDNS state as a normal recovery path.
