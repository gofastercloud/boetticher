# Lost OPNsense

OPNsense is the security boundary, so guest recovery alone is not a substitute. Recreate VM 100 from the exact tested OPNsense patch, restore the HOME/WAN and untagged `vmbr1` trunk interfaces, establish `10.10.99.1/24` MGMT reachability, create the scoped API identity, and capture its credential directly into encrypted SOPS input.

The unattended install, interface assignment, API identity creation, Kea/firewall convergence, temporary privilege removal, and wiped-environment repeat are a release-blocking integration gate. The current repository contains the deterministic contract and API adapters, but live recovery remains `HOLD` until this sequence is qualified.
