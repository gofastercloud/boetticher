# Physical trunk

V1 can operate in virtual-only mode with no physical member on `vmbr1`. This lets the controller build and test the virtual platform before a suitable switch or second NIC exists. It does not give physical clients access to all internal VLANs.

The completed physical path is a second Proxmox NIC carrying an 802.1Q trunk to a managed switch. Switch access ports map to TRUSTED, SANDBOX, or MGMT. Use client/port isolation for physical SANDBOX peers where the switch supports it.

Use:

```sh
homelab network trunk status --site my-homelab
homelab network trunk attach enp3s0 --site my-homelab --confirm
homelab network trunk detach enp3s0 --site my-homelab --confirm
```

The API-backed transition checks the recorded HOME/bootstrap address, rejects the current upstream interface, requires explicit confirmation, preserves VLAN-aware bridge state, updates the canonical model only after the API change, and regenerates projections. Live rollback and acceptance must be tested on Proxmox; the controller does not scan for alternate interfaces or guess recovery paths.
