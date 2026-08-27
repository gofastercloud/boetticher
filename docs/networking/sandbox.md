# SANDBOX

SANDBOX is VLAN 40, `10.10.40.0/24`, gateway `10.10.40.1`. It is for test,
untrusted, or externally managed devices. Its default policy allows Internet
egress and gateway DHCP/DNS/NTP, while denying TRUSTED, SERVERS, INFRA, and
MGMT.

Managed mode provides the gateway services on `lab-fw-01`. External mode
requires the operator appliance to provide the same observable behavior. The
SANDBOX resolver must not expose the broad `lab.home.arpa` namespace. Lease
names may be published under `sandbox.lab.home.arpa` for administration; that
does not make the clients platform-owned.
