# Changed bootstrap address

The initial Proxmox frontend address comes from the existing HOME router and may change. Reserve its DHCP lease in that router where possible.

If it changes, use only the known new address:

```sh
boetticher bootstrap-endpoint set 192.0.2.10 --site my-boetticher
boetticher ssh-config --site my-boetticher --force
boetticher doctor --site my-boetticher --live
```

Doctor checks TCP/22 and compares the returned public SSH host-key evidence with the recorded Proxmox identity. If the key differs, stop and investigate replacement/stale-address risk. boetticher never scans or guesses addresses.
