# Recovery

The minimum control-plane recovery set is:

```text
private site repository
+ independent Age private-identity copy
```

The repository contains desired state, encrypted secrets, version locks, and non-secret evidence. It does not contain the Age private identity, OpenTofu state, plans, caches, bootstrap state, or temporary credentials.

Recovery paths:

- **Proxmox OS loss:** install the supported release, restore the HOME-side address, set the endpoint, and repeat the qualified bootstrap.
- **OPNsense loss:** recreate VM 100, repeat the exact installer/interface/API gate, import the resulting API credential through stdin, then converge policy.
- **DNS loss:** rebuild either DNS node independently; dual DNS/NTP is service redundancy, not host redundancy.
- **Changed HOME DHCP address:** use `boetticher bootstrap-endpoint set ADDRESS`, regenerate SSH, and run `boetticher doctor --live`; never scan or guess.
- **Physical NIC renamed or replaced:** use `boetticher preflight --live` to compare stable MAC/PCI identity, review the proposed binding, and use the explicit trunk workflow. Do not silently rewrite a renamed or ambiguous interface.
- **Failed trunk mutation:** retain the HOME-side path, inspect `boetticher network trunk status --live`, and treat an uncertain rollback as `HOLD` until the Proxmox network state and bastion path are reverified.
- **Lost operator device:** issue a new SSH key/client certificate and record/revoke the old certificate as appropriate.
- **Data-disk loss:** restore Proxmox backups if available, then reconstruct platform state from the site repository and Age identity. Same-disk backups are not disaster recovery.

No recovery is considered proven until the deployed model revision, authenticated access path, and negative security journeys are reverified.
