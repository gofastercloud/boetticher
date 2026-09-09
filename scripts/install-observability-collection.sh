#!/bin/sh
set -eu

usage() {
  cat <<'EOF'
Usage: boetticher-install-observability-collection [--root PATH] --arch amd64|arm64 --name NAME --address IPv4 --kind controller|host|runtime --collector-url URL --read-token-hash HASH

Installs the pinned node_exporter and the owned systemd-journal-upload
configuration for one Boetticher Linux node. Journal upload uses the explicit
system CA bundle and no client certificate; private material is never accepted
as a command-line argument.
EOF
}

die() { printf 'Observability collection installer: FAIL — %s\n' "$1" >&2; exit 1; }
root=/
arch=
node_name=
node_address=
node_kind=
collector_url=
read_token_hash=
asset_root=${BOETTICHER_OBSERVABILITY_ASSETS:-}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --root) [ "$#" -ge 2 ] || die '--root requires a path'; root=$2; shift 2 ;;
    --arch) [ "$#" -ge 2 ] || die '--arch requires amd64 or arm64'; arch=$2; shift 2 ;;
    --name) [ "$#" -ge 2 ] || die '--name requires a managed node name'; node_name=$2; shift 2 ;;
    --address) [ "$#" -ge 2 ] || die '--address requires an IPv4 address'; node_address=$2; shift 2 ;;
    --kind) [ "$#" -ge 2 ] || die '--kind requires controller, host, or runtime'; node_kind=$2; shift 2 ;;
    --collector-url) [ "$#" -ge 2 ] || die '--collector-url requires an HTTPS URL'; collector_url=$2; shift 2 ;;
    --read-token-hash) [ "$#" -ge 2 ] || die '--read-token-hash requires a bcrypt hash'; read_token_hash=$2; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option $1" ;;
  esac
done
case "$root" in /*) ;; *) die '--root must be an absolute path' ;; esac
case "$arch" in amd64|arm64) ;; *) die '--arch must be amd64 or arm64' ;; esac
case "$node_kind" in controller) expected_name=controller; expected_arch=arm64 ;;
  host) expected_name=proxmox-host; expected_arch=amd64 ;;
  runtime) expected_name=lab-monitor-01; expected_arch=amd64 ;;
  *) die 'node kind is not an allowlisted Boetticher Linux target' ;;
esac
[ "$node_name" = "$expected_name" ] || die 'node name does not match the target kind'
[ "$arch" = "$expected_arch" ] || die 'node architecture does not match the target kind'
case "$node_address" in ''|*[!0-9.]*) die 'node address must be an IPv4 address' ;; esac
if ! printf '%s\n' "$node_address" | awk -F. 'NF == 4 { for (i = 1; i <= 4; i++) if ($i !~ /^[0-9]+$/ || $i < 0 || $i > 255) exit 1; exit 0 } { exit 1 }'; then
  die 'node address must be an IPv4 address'
fi
if [ "$node_kind" = runtime ] && [ "$node_address" != 10.10.10.20 ]; then
  die 'runtime address is not the owned observability guest address'
fi
case "$collector_url" in https://[A-Za-z0-9.-]*:443) ;; *) die 'collector URL must be the pinned HTTPS ingest origin on port 443' ;; esac
case "$read_token_hash" in '$2a$'*|'$2b$'*|'$2y$'*) ;; *) die 'node exporter read token hash must be bcrypt' ;; esac

root=${root%/}; [ -n "$root" ] || root=/
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[ -n "$asset_root" ] || asset_root=$script_dir/../internal/observability/assets
catalog=$asset_root/catalog.json
[ -r "$catalog" ] || die "provider catalog is missing: $catalog"

root_path() { printf '%s%s\n' "$root" "$1"; }
service_user=boetticher-node-exporter
binary_path=$(root_path /usr/local/bin/node_exporter)
service_path=$(root_path /etc/systemd/system/boetticher-node-exporter.service)
web_config=$(root_path /etc/boetticher/observability/node-exporter-web.yml)
journal_config=$(root_path /etc/systemd/journal-upload.conf.d/boetticher.conf)
journal_dropin=$(root_path /etc/systemd/system/systemd-journal-upload.service.d/boetticher.conf)
marker=$(root_path "/var/lib/boetticher/observability/collection/$node_name.managed")
guest_binary=/usr/local/bin/node_exporter
guest_web_config=/etc/boetticher/observability/node-exporter-web.yml
listen_address=$node_address

for path in "$service_path" "$web_config" "$journal_config"; do
  if [ -e "$path" ] && ! grep -Fq 'Boetticher observability collection' "$path"; then
    die "refusing to replace an unowned existing path: $path"
  fi
done
[ "$root" != / ] || [ -x /usr/lib/systemd/systemd-journal-upload ] || die 'systemd-journal-upload is missing; install systemd-journal-remote before collection apply'

catalog_value() {
  key=$1; field=$2
  awk -F'"' -v key="$key" -v field="$field" '$2 == key { for (i = 1; i <= NF; i++) if ($i == field) { print $(i + 2); exit } }' "$catalog"
}
entry=node-exporter-$arch
download_url=$(catalog_value "$entry" url)
expected_sha=$(catalog_value "$entry" sha256)
case "$download_url" in https://*) ;; *) die "catalog entry $entry has no HTTPS URL" ;; esac
case "$expected_sha" in ''|*[!0-9a-fA-F]*) die "catalog entry $entry has an invalid SHA-256" ;; esac
[ "${#expected_sha}" -eq 64 ] || die "catalog entry $entry has an invalid SHA-256"

case "$root" in
  /) cache=${BOETTICHER_OBSERVABILITY_CACHE:-/var/cache/boetticher/observability} ;;
  *) cache=${BOETTICHER_OBSERVABILITY_CACHE:-$root/var/cache/boetticher/observability} ;;
esac
install -d -m 0750 "$cache"
work=$(mktemp -d "$cache/.collection.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
archive=$work/node-exporter.tar.gz
persistent=$cache/$entry-$expected_sha.tar.gz
if [ -f "$persistent" ] && [ "$(sha256sum "$persistent" | awk '{print $1}')" = "$expected_sha" ]; then
  cp "$persistent" "$archive"
else
  rm -f "$persistent"
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --max-time 600 --continue-at - --output "$archive.partial" "$download_url" || die "download failed for $entry"
  [ "$(sha256sum "$archive.partial" | awk '{print $1}')" = "$expected_sha" ] || die "checksum verification failed for $entry"
  mv -f "$archive.partial" "$persistent"
  cp "$persistent" "$archive"
fi

safe_archive_members() {
  tar -tzf "$1" | awk 'BEGIN { bad=0 } { raw=$0; sub(/\/$/,"",raw); if (raw == "" || raw ~ /^\// || raw ~ /(^|\/)\.\.($|\/)/ || raw ~ /\\/) { print "unsafe archive member: " $0 > "/dev/stderr"; bad=1 } } END { exit bad }'
}
safe_archive_members "$archive" || die 'unsafe node_exporter archive rejected'
mkdir -p "$work/extract"
tar -xzf "$archive" -C "$work/extract" --no-same-owner --no-same-permissions
source=$(find "$work/extract" -type f -name node_exporter -print | head -n 1)
[ -n "$source" ] && [ -s "$source" ] || die 'node_exporter binary is missing from the archive'

if [ "$root" = / ]; then
  if ! getent passwd "$service_user" >/dev/null 2>&1; then
    useradd --system --user-group --home-dir /var/lib/boetticher/observability --no-create-home --shell /usr/sbin/nologin "$service_user" || die 'cannot create node_exporter account'
  fi
else
  passwd_file=$(root_path /etc/passwd)
  if ! awk -F: -v account="$service_user" '$1 == account { found=1 } END { exit !found }' "$passwd_file" 2>/dev/null; then
    useradd --root "$root" --system --user-group --home-dir /var/lib/boetticher/observability --no-create-home --shell /usr/sbin/nologin "$service_user" || die 'cannot create staged node_exporter account'
  fi
fi

install -d -m 0755 "$(dirname "$binary_path")" "$(dirname "$service_path")" "$(dirname "$web_config")" "$(dirname "$journal_config")" "$(dirname "$journal_dropin")" "$(dirname "$marker")"
install -m 0755 "$source" "$binary_path.new"
mv -f "$binary_path.new" "$binary_path"
cat > "$work/web.yml" <<EOF
# Boetticher observability collection
basic_auth_users:
  boetticher: $read_token_hash
EOF
install -m 0640 "$work/web.yml" "$web_config.new"
mv -f "$web_config.new" "$web_config"
cat > "$work/unit" <<EOF
# Boetticher observability collection
[Unit]
Description=Boetticher node exporter
After=network-online.target
[Service]
User=$service_user
Group=$service_user
LoadCredential=node-exporter-web:$guest_web_config
ExecStart=$guest_binary --web.listen-address=$listen_address:9100 --web.config.file=/run/credentials/boetticher-node-exporter.service/node-exporter-web
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=$guest_web_config
ReadWritePaths=/var/lib/boetticher/observability
[Install]
WantedBy=multi-user.target
EOF
install -m 0644 "$work/unit" "$service_path.new"
mv -f "$service_path.new" "$service_path"
cat > "$work/journal" <<EOF
# Boetticher observability collection
[Upload]
URL=$collector_url
TrustedCertificateFile=/etc/ssl/certs/ca-certificates.crt
EOF
install -m 0644 "$work/journal" "$journal_config.new"
mv -f "$journal_config.new" "$journal_config"
cat > "$work/journal-dropin" <<EOF
# Boetticher observability collection
[Service]
ExecStart=
ExecStart=/usr/lib/systemd/systemd-journal-upload --key=- --cert=- --save-state=/var/lib/systemd/journal-upload/state
Restart=on-failure
RestartSec=10s
EOF
install -m 0644 "$work/journal-dropin" "$journal_dropin.new"
mv -f "$journal_dropin.new" "$journal_dropin"
printf '%s\n' 'owned' > "$marker.new"
mv -f "$marker.new" "$marker"

if [ "$root" = / ]; then
  chown "$service_user:$service_user" "$binary_path"
  systemctl daemon-reload
  systemctl enable boetticher-node-exporter.service
  systemctl restart boetticher-node-exporter.service
  systemctl is-active --quiet boetticher-node-exporter.service || die 'node_exporter did not become active'
  systemctl enable systemd-journal-upload.service
  systemctl restart systemd-journal-upload.service
  systemctl is-active --quiet systemd-journal-upload.service || die 'systemd-journal-upload did not become active'
else
  systemctl --root="$root" enable boetticher-node-exporter.service
  systemctl --root="$root" enable systemd-journal-upload.service
fi
printf 'observability collection: PASS (%s)\n' "$node_name"
