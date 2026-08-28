# Central logging

`logging` is a mandatory first-party module. It runs a small Debian appliance
with `systemd-journal-remote` and stores a bounded host-split journal at
`/var/log/journal/remote`. The appliance is backed up; the high-churn journal
volume is explicitly `backup: false`.

Managed Linux endpoints retain bounded local journals and asynchronously upload
over HTTPS/mTLS to `logs.lab.home.arpa:19532`. Upload failure does not stop an
application, DNS, routing, or local journald. The collector does not upload its
own journal recursively. Use `boetticher logs` for bounded read-only access.

The Proxmox host uses the same endpoint-local upload path. Deployment pins the
collector hostname to the managed collector in `/etc/hosts` and permits only
the exact collector TCP port through the managed gateway; the HOME resolver
path is not changed.

Core also pins the platform DNS pair in each LXC's Proxmox network contract so
guest reboot does not restore the HOME resolver before the appliance can upload
logs.

The endpoint client certificate and key are endpoint-local. The boetticher CA
and recovery authority remain on the controller.
