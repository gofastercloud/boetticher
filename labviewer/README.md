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

The listener is localhost-only and should be reached through the existing
private LAN/Tailnet Caddy boundary. The service account has read access to the
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
