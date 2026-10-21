# Lab snapshot portal

The installed Controller publishes a bounded, timestamped lab snapshot every
five minutes. The viewer serves the human page at `/lab/`, machine data at
`/lab/snapshot.json`, and selected documentation at `/lab/docs/`.

The snapshot contains redacted desired intent, allowlisted live facts, source
timestamps, explicit unknown/stale states, and links. It never publishes
credentials, private keys, raw configuration, or arbitrary logs. Holmes reads
the same bounded publication; it does not receive SSH or Proxmox credentials.

## Run

```sh
go run ./labviewer --lab /etc/boetticher/lab.yml --listen 127.0.0.1:8090
```

This local example listens on localhost only. The installed Controller unit
(templated from
`controller/roles/controller-baseline/templates/boetticher-labviewer.service.j2`;
`labviewer/deploy/boetticher-labviewer.service` is the standalone copy) listens
on the
Controller SERVERS address `10.10.20.10:8090`, which the managed firewall opens
only to the observability runtime; its Caddy frontend publishes the portal as
`lab.<public domain>` and `labviewer.<public domain>`. The operator guide is in
[docs/controller.md](../docs/controller.md#lab-snapshot-portal). The service account has read access to the
lab configuration and documentation and write access only to the snapshot
publication directory.

Optional explicit publications:

```yaml
control_surfaces:
  - name: Firewall
    description: OpenWrt administration
    url: https://fw-admin.example.com
    group: Operate
    icon: ⌁
```
