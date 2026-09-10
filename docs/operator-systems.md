# Operator managed systems

Boetticher registers an existing Proxmox VM or Linux Container as a user
system. Proxmox remains the guest owner; Boetticher stores only identity and
derived network policy.

```text
boetticher host register-system NAME --vmid VMID --address IPv4 --port PORT [--check] [--plan|--yes]
boetticher host list-systems
boetticher host system-status NAME
boetticher host unregister-system NAME --plan|--yes
```

Registration requires one existing guest with one NIC on `vmbr1`, SERVERS
VLAN tag 20. It discovers kind, name, and MAC and refuses ambiguity,
product-owned guests, conflicting identities, and VMIDs outside the user range
500-899. DNS, DHCP, and the firewall capability must already be enabled; add
`--check` only when observability is enabled as well. It never manages the
guest.

The entry drives one SERVERS DHCP reservation and one narrow TRUSTED to
SERVERS TCP allow. `--check` adds a bounded observability TCP check. DHCP is
the DNS source for the system name, so no duplicate A record is emitted.

`--plan` is read-only. Mutations require `--yes`, save intent before provider
reconciliation, and retain intent when application fails. Unregistration
removes only owned network policy and works if the guest is absent.

The MVP supports IPv4 DHCP identity, one TCP port, and SERVERS only. It does
not install software, provision certificates, manage guest lifecycle, support
static addressing, arbitrary URLs, or provide a general monitoring language.

## Example: print server

Create or select the VM/LXC in Proxmox and configure exactly one NIC on
`vmbr1`, VLAN 20. Install and operate the print service and any USB or device
integration through the guest's own operator procedure. In Boetticher, choose
an unused SERVERS address outside the DHCP pool, platform reservations, and
probe range, then review and apply:

```text
boetticher host register-system print-server --vmid 501 --address 10.10.20.61 --port 631 --check --plan
boetticher host register-system print-server --vmid 501 --address 10.10.20.61 --port 631 --check --yes
boetticher host system-status print-server
boetticher host unregister-system print-server --plan
boetticher host unregister-system print-server --yes
```

Boetticher permanently excludes guest creation, deletion, updates, application
installation, USB assignment, and backup ownership. A TCP check proves only
that the port answers; it does not prove printing, same-VLAN reachability, or
IPv6 behavior. Omitting `--check` does not create monitoring. The operator
must renew the DHCP lease in the guest after registration when it uses DHCP.
If provider application fails, saved intent remains available: rerun
`boetticher module dhcp apply --yes` (and `boetticher module dns apply --yes`
when DNS also needs recovery), then rerun the same registration or
unregistration command. Retrying an already absent removal reconciles the
current desired provider state and reports PASS when cleanup is complete.

V2 candidates include additional zones or ports, static identity, richer
checks, and aliases. They do not change the guest ownership boundary.

## Example: OctoPrint on a USB printer

For an operator-managed printer, create the LXC and install OctoPrint through
the normal Proxmox and guest administration path first. Boetticher then
registers the completed guest; it does not create the guest or install its
software.

1. On the Proxmox host, identify the printer by its physical USB port and
   vendor/product identity. Prefer the stable `/dev/serial/by-id` identity when
   selecting the device, and pass only the resolved character device into the
   LXC. Verify the guest sees the expected `/dev/ttyUSB*` or `/dev/ttyACM*` and
   grant access only to the OctoPrint service account.
2. Create one unprivileged LXC with one DHCP NIC on `vmbr1`, VLAN 20, and an
   unused address outside the SERVERS pool. Install OctoPrint in a dedicated
   virtual environment and run it as a non-root systemd service listening on
   its chosen port.
3. Verify the service locally in the guest and record the guest VMID, name,
   NIC MAC, chosen address, port, and USB identity. A working HTTP page alone
   does not prove printer serial access.
4. From the installed Controller, review and apply the registration:

   ```text
   boetticher host register-system octoprint --vmid VMID --address SERVERS_ADDRESS --port 5000 --check --plan
   boetticher host register-system octoprint --vmid VMID --address SERVERS_ADDRESS --port 5000 --check --yes
   boetticher host system-status octoprint
   ```

   Registration projects the DHCP reservation and narrow monitoring/firewall
   policy. Renew the guest's DHCP lease after a successful registration, then
   verify that it receives the reserved address and that the monitoring check
   passes.
5. Complete OctoPrint's first-run configuration in its own UI, select the
   passed-through serial device, and perform a controlled printer connection
   test. The Boetticher `--check` result proves only the configured TCP port;
   it does not claim OctoPrint API, serial, or print-job success.
