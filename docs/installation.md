# Installation

Boetticher runs from a macOS or Linux controller and builds a small platform
on a fresh amd64 Proxmox host. The controller keeps the private site
repository, encrypted secrets, and recovery authority; the Proxmox host runs
the platform.

## Before you begin

You need:

- a fresh supported Proxmox VE installation reachable from its HOME/upstream
  network;
- a macOS or Linux controller with the Boetticher binary and SSH; and
- one Ethernet interface for the default managed setup.

A second interface and a VLAN-aware switch are only needed for a physical
trunk or external-firewall mode. Choose either the single-disk or
dedicated-data-disk storage profile before the first deployment.

If you are working from a source checkout, build the controller with
`make build` and use `./bin/boetticher`. A release binary does not need the Go
toolchain at runtime. Ansible Core is required on the controller; SOPS 3.13.3
and age 1.3.1 are included in the Boetticher build.

## 1. Create a site

```text
boetticher init --site-dir my-boetticher
```

This creates a small `site.yml`, encrypted-secret metadata, and recovery
state. The Age identity is kept outside the site directory by default at
`~/.config/boetticher/age/identity.txt`. Keep an independent recovery copy
before bootstrapping. `init` reuses an existing identity after checking that it
belongs to the site and will not overwrite it.

For managed mode, `init` also creates the stable MAC address used by the
gateway's upstream interface. Reserve that MAC in the existing HOME/upstream
DHCP service before deployment; the resulting address remains upstream state,
not site configuration.

## 2. Prepare the fresh host

Find the address Proxmox received from the existing HOME/upstream DHCP service
and record it:

```text
boetticher bootstrap-endpoint set PROXMOX_HOME_IP --site my-boetticher
```

`PROXMOX_HOME_IP` is a placeholder for the real address. Boetticher does not
scan the network for the host.

Run the read-only hardware and configuration check:

```text
boetticher preflight --site my-boetticher --live
```

Managed mode starts with a virtual-only internal bridge. If you want a
physical trunk, select the interface reported by preflight and pass
`--trunk-interface IFACE` to the guarded bootstrap. External-firewall mode
always requires an explicitly selected physical trunk.

## 3. Bootstrap trust and storage

Copy the Proxmox cluster CA to the controller through a trusted path, then
run:

```text
boetticher bootstrap --site my-boetticher --recovery-confirmed --proxmox-ca /path/to/pve-root-ca.pem
```

At the first SSH connection, verify the displayed Proxmox host fingerprint.
The enrolled identity is then used for later connections. Do not use a
`ssh-keyscan` result as verification evidence, and do not use `--insecure`
unless you are following the advanced recovery procedure.

`--recovery-confirmed` means that the independent Age recovery copy is safe
and available. If the site uses `dedicated-data-disk`, review the exact stable
`/dev/disk/by-id/...` device and repeat with `--storage-confirmed`:

```text
boetticher bootstrap --site my-boetticher --recovery-confirmed --storage-confirmed --proxmox-ca /path/to/pve-root-ca.pem
```

Bootstrap prepares the host and deployment trust. It does not deploy the
platform guests yet.

## 4. Deploy and check the platform

Review the plan first:

```text
boetticher deploy --site my-boetticher --dry-run --proxmox-ca /path/to/pve-root-ca.pem
```

Apply it:

```text
boetticher deploy --site my-boetticher --proxmox-ca /path/to/pve-root-ca.pem
boetticher status --site my-boetticher --live
```

`deploy` is the normal command that applies the complete platform. It creates
the managed gateway when selected, brings up DNS/NTP, monitoring, logs, the
portal, backups, and any enabled optional modules. `status` gives the normal
operator view; use `doctor` or the [troubleshooting guide](troubleshooting.md)
when it points to a specific problem.

The generated portal and the [operations guide](operations.md) are useful
places to start after the first deployment. Create client certificates with
the [access guide](access/client-certificates.md) before opening the protected
platform UIs.

## External-firewall mode

Choose this mode when another appliance owns routing, NAT, DHCP, and the
network boundary:

```text
boetticher init --site-dir my-boetticher --external-firewall
```

The appliance must carry VLANs 5, 10, 20, 30, 40, and 99 on a distinct
physical trunk and provide the six fixed gateways. Boetticher publishes the
contract and configures its own platform side; it does not configure, back up,
or recover the external appliance. Follow the [external-firewall guide](networking/external-firewall.md)
before bootstrap.

## If something goes wrong

Keep the site repository, Age identity, CA authority, and declared backups
together as a recovery set. A failed deployment retains its bounded retry path;
cleanup failures require the recovery instructions before you treat the host
as settled. Local backups share the storage failure domain, so keep an
independent copy for anything you care about.

For detailed trust, storage, and rebuild procedures, see [recovery](recovery/recovery.md),
[security](security-model.md), and [dedicated storage](storage/dedicated-data-disk.md).
