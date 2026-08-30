# Lost Proxmox

The recovered bootstrap path is the initial root authority. It recreates the
temporary root deployment window, while durable `labadmin` remains
unprivileged with no general sudo authority. A successful deployment removes the
temporary key and host root-login allowance. An interrupted deployment leaves
that window for retry; cleanup failure is a `FAIL` requiring authenticated root
recovery before retry.

Install the supported Proxmox release, restore the HOME-side DHCP path, recover the site repository and Age identity, then record the address with `bootstrap-endpoint set`, run `preflight`, and follow the qualified bootstrap sequence. Boetticher discovers and validates the single Proxmox API node identifier during the SSH/API bootstrap path; the logical platform identity `lab-proxmox-01` remains distinct. The normal internal recovery path is still through the Proxmox bastion. Do not claim recovery until the deployed model revision, SSH host key, authenticated journeys, and negative security tests are reverified.
