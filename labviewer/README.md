# Lab Viewer

Small, read-only control-surface directory for the installed Boetticher lab.
It reads `lab.yml` on every request (and the browser refreshes every 15 seconds),
redacts secret-shaped values before returning configuration, and publishes links
from `control_surfaces`, `gateway.publish`, and the existing observability/media
conventions. The embedded page is a zero-dependency fallback; the same binary
can also maintain a Homepage config directory with `--homepage-config`.

## Run

```sh
go run ./labviewer --lab /etc/boetticher/lab.yml --listen 127.0.0.1:8090
```

Put Caddy in front of the listener at a private hostname such as
`labviewer.example.com`. The process never writes `lab.yml` and has no
mutation endpoints.

For Homepage-backed deployment, run the binary with
`--homepage-config /var/lib/boetticher/homepage/config --refresh-interval 15s` and mount
that directory into Homepage's `/app/config`. The adapter atomically writes
`services.yaml`, `bookmarks.yaml`, `settings.yaml`, and the Breaking Prod image.
Homepage's own refresh mechanism should be used after a config change; the
adapter does not need write access to the lab configuration.

`deploy/homepage-compose.yaml` pins Homepage to v1.13.2 and binds it only to
localhost. Put the Caddy authentication policy in front of that listener; do
not expose the Homepage port directly.

Deployment assets are in `deploy/`: a hardened systemd unit, Caddy snippet, and
an install helper. The service account only needs read access to
`/etc/boetticher/lab.yml`.

Optional explicit publications:

```yaml
control_surfaces:
  - name: Firewall
    description: OpenWrt administration
    url: https://fw-admin.example.com
    group: Operate
    icon: ⌁
```
