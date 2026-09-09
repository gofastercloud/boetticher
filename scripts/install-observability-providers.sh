#!/bin/sh
set -eu

usage() {
  cat <<'EOF'
Usage: boetticher-install-observability-providers PROVIDER [--root PATH]

PROVIDER is one of victorialogs, victoriametrics, grafana, gatus, bifrost, caddy, or holmes.
--root is an optional absolute filesystem root used for offline staging; the
default is the running Debian guest (/, with systemd and local accounts).
EOF
}

die() {
  printf 'Observability provider installer: FAIL — %s\n' "$1" >&2
  exit 1
}

provider=${1-}
[ "$provider" = '--help' ] && { usage; exit 0; }
case "$provider" in
  victorialogs|victoriametrics|grafana|gatus|bifrost|caddy|holmes) ;;
  *) usage >&2; exit 2 ;;
esac
config_digest=${BOETTICHER_OBSERVABILITY_CONFIG_DIGEST:-}
case "$config_digest" in
  ''|*[!0-9a-fA-F]*) [ -z "$config_digest" ] || die 'observability config digest is invalid' ;;
  *) [ "${#config_digest}" -eq 64 ] || die 'observability config digest is invalid' ;;
esac
public_domain=${BOETTICHER_OBSERVABILITY_PUBLIC_DOMAIN:-}
metrics_retention=${BOETTICHER_OBSERVABILITY_METRICS_RETENTION_DAYS:-30}
logs_retention=${BOETTICHER_OBSERVABILITY_LOGS_RETENTION_DAYS:-7}
pushover_enabled=${BOETTICHER_OBSERVABILITY_PUSHOVER_ENABLED:-false}
pushover_title=${BOETTICHER_OBSERVABILITY_PUSHOVER_TITLE:-Boetticher observability}
pushover_priority=${BOETTICHER_OBSERVABILITY_PUSHOVER_PRIORITY:-0}
case "$metrics_retention" in ''|*[!0-9]*) die 'metrics retention must be a day count' ;; esac
case "$logs_retention" in ''|*[!0-9]*) die 'logs retention must be a day count' ;; esac
[ "$metrics_retention" -ge 1 ] && [ "$metrics_retention" -le 3650 ] || die 'metrics retention must be between 1 and 3650 days'
[ "$logs_retention" -ge 1 ] && [ "$logs_retention" -le 3650 ] || die 'logs retention must be between 1 and 3650 days'
case "$pushover_enabled" in true|false) ;; *) die 'Pushover enabled setting must be true or false' ;; esac
case "$pushover_priority" in -2|-1|0|1) ;; *) die 'Pushover priority must be between -2 and 1' ;; esac
case "$pushover_title" in *[!A-Za-z0-9._\ -]*) die 'Pushover title contains unsupported characters' ;; esac
[ "${#pushover_title}" -le 250 ] || die 'Pushover title exceeds 250 characters'
if [ "$provider" = caddy ]; then
  [ -n "$public_domain" ] || die 'Caddy public domain is required'
  case "$public_domain" in *[!A-Za-z0-9.-]*|'') die 'Caddy public domain is invalid' ;; esac
  case "$public_domain" in *.*.*|*.*) ;; *) die 'Caddy public domain must contain a dot' ;; esac
fi
shift
root=/
while [ "$#" -gt 0 ]; do
  case "$1" in
    --root)
      [ "$#" -ge 2 ] || die '--root requires a path'
      root=$2
      shift 2
      ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option $1" ;;
  esac
done
case "$root" in
  /*) ;;
  *) die '--root must be an absolute path' ;;
esac

wait_for_local_http() {
  url=$1
  deadline=$(( $(date +%s) + 30 ))
  while :; do
    if ! systemctl is-active --quiet "$unit"; then
      die "$unit stopped before its local health endpoint became ready"
    fi
    if curl --fail --silent --show-error --max-time 5 "$url" >/dev/null 2>"$work/health-error"; then
      return 0
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      detail=$(tail -n 1 "$work/health-error" 2>/dev/null || true)
      [ -n "$detail" ] || detail='request failed'
      die "$unit local health endpoint did not become ready within 30s: $detail"
    fi
    sleep 1
  done
}
root=${root%/}
[ -n "$root" ] || root=/

# shellcheck disable=SC1007
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1007
asset_root=${BOETTICHER_OBSERVABILITY_ASSETS:-$(CDPATH= cd -- "$script_dir/../../observability/assets" && pwd)}
catalog=$asset_root/catalog.json
[ -r "$catalog" ] || die "provider catalog is missing: $catalog"

case "$provider" in
  victorialogs) user=victorialogs; unit=victorialogs.service; data_dir=/var/lib/victorialogs; archive_name=vl.tar.gz ;;
  victoriametrics) user=victoriametrics; unit=victoriametrics.service; data_dir=/var/lib/victoriametrics; archive_name=vm.tar.gz ;;
  grafana) user=grafana; unit=grafana.service; data_dir=/var/lib/boetticher/observability/state/grafana; archive_name=grafana.deb ;;
  gatus) user=gatus; unit=gatus.service; data_dir=/var/lib/boetticher/observability/state/gatus; archive_name=gatus ;;
  bifrost) user=bifrost; unit=bifrost.service; data_dir=/var/lib/bifrost; archive_name=bifrost ;;
  caddy) user=caddy; unit=caddy.service; data_dir=/var/lib/boetticher/observability/state/caddy; archive_name=caddy ;;
  holmes) user=holmes; data_dir=/var/lib/boetticher/holmes; archive_name=holmes ;;
esac

holmes_root=${BOETTICHER_OBSERVABILITY_HOLMES_ROOT:-$asset_root/../holmes}
holmes_lock=$holmes_root/requirements.lock
if [ ! -f "$holmes_lock" ]; then
  holmes_lock=$script_dir/../images/aiops/runtime/requirements.lock
fi

catalog_value() {
  key=$1
  field=$2
  awk -F'"' -v key="$key" -v field="$field" '$2 == key { for (i = 1; i <= NF; i++) if ($i == field) { print $(i + 2); exit } }' "$catalog"
}

catalog_entry() {
  entry=$1
  url=$(catalog_value "$entry" url)
  sha=$(catalog_value "$entry" sha256)
  case "$url" in https://*) ;; *) die "catalog entry $entry has no HTTPS URL" ;; esac
  case "$sha" in ''|*[!0-9a-fA-F]*) die "catalog entry $entry has an invalid SHA-256" ;; esac
  [ "${#sha}" -eq 64 ] 2>/dev/null || die "catalog entry $entry has an invalid SHA-256"
  printf '%s\t%s\n' "$url" "$sha"
}

sha256_matches() {
  expected=$1
  file=$2
  [ "$(sha256sum "$file" | awk '{print $1}')" = "$expected" ]
}

download_verified() {
  entry=$1
  destination=$2
  catalog_record=$(catalog_entry "$entry")
  url=$(printf '%s\n' "$catalog_record" | awk -F '\t' '{print $1}')
  expected=$(printf '%s\n' "$catalog_record" | awk -F '\t' '{print $2}')
  persistent="$cache/$entry-$expected-$(basename "$destination")"
  partial="$persistent.partial"
  if [ -f "$persistent" ] && sha256_matches "$expected" "$persistent"; then
    cp "$persistent" "$destination"
    return 0
  fi
  rm -f "$persistent"
  # Keep partial bytes in the owned cache. A retry resumes only the exact
  # catalog-addressed object and verifies the full checksum before use.
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --max-time 600 --continue-at - --output "$partial" "$url" || die "download failed for catalog entry $entry"
  sha256_matches "$expected" "$partial" || die "checksum verification failed for catalog entry $entry"
  mv -f "$partial" "$persistent"
  cp "$persistent" "$destination"
}

safe_archive_members() {
  archive=$1
  tar -tzf "$archive" | awk '
    BEGIN { bad = 0 }
    {
      raw = $0
      sub(/\/$/, "", raw)
      if (raw == "" || raw ~ /^\// || raw ~ /(^|\/)\.\.($|\/)/ || raw ~ /\\/ || raw ~ /(^|\/)\.($|\/)/) {
        printf "unsafe archive member: %s\n", $0 > "/dev/stderr"
        bad = 1
      }
    }
    END { exit bad }
  '
}

extract_tar_binary() {
  archive=$1
  wanted=$2
  destination=$3
  extraction=$work/extract
  mkdir -p "$extraction"
  safe_archive_members "$archive" || die "unsafe archive rejected: $archive"
  tar --extract --file "$archive" --directory "$extraction" --no-same-owner --no-same-permissions
  found=$(find "$extraction" -type f -name "$wanted" -print | head -n 1)
  [ -n "$found" ] || die "archive does not contain expected binary $wanted"
  [ -s "$found" ] || die "archive binary $wanted is empty"
  install -m 0755 "$found" "$destination.ready"
}

root_path() { printf '%s%s\n' "$root" "$1"; }

ensure_account() {
  account=$1
  home=$2
  if [ "$root" = / ]; then
    if ! getent passwd "$account" >/dev/null 2>&1; then
      useradd --system --user-group --home-dir "$home" --create-home --shell /usr/sbin/nologin "$account" || die "cannot create service account $account"
    fi
  else
    passwd_file=$(root_path /etc/passwd)
    if [ ! -r "$passwd_file" ] || ! awk -F: -v account="$account" '$1 == account { found=1 } END { exit !found }' "$passwd_file"; then
      useradd --root "$root" --system --user-group --home-dir "$home" --create-home --shell /usr/sbin/nologin "$account" || die "cannot create staged service account $account"
    fi
  fi
}

install_owned_dir() {
  directory=$1
  owner=$2
  mode=$3
  install -d -m "$mode" "$directory"
  if [ "$root" = / ]; then
    chown "$owner:$owner" "$directory"
  else
    owner_id=$(awk -F: -v account="$owner" '$1 == account { print $3 ":" $4; exit }' "$(root_path /etc/passwd)")
    [ -n "$owner_id" ] || die "staged service account is missing: $owner"
    chown "$owner_id" "$directory"
  fi
}

install_atomic() {
  mode=$1
  source=$2
  destination=$3
  install -d -m 0755 "$(dirname "$destination")"
  install -m "$mode" "$source" "$destination.ready"
  mv -f "$destination.ready" "$destination"
}

chown_owned() {
  target=$1
  owner=$2
  if [ "$root" = / ]; then
    chown "$owner:$owner" "$target"
  else
    owner_id=$(awk -F: -v account="$owner" '$1 == account { print $3 ":" $4; exit }' "$(root_path /etc/passwd)")
    [ -n "$owner_id" ] || die "staged service account is missing: $owner"
    chown "$owner_id" "$target"
  fi
}

chown_root_group() {
  target=$1
  group=$2
  if [ "$root" = / ]; then
    chown "root:$group" "$target"
  else
    group_id=$(awk -F: -v name="$group" '$1 == name { print $3; exit }' "$(root_path /etc/group)")
    [ -n "$group_id" ] || die "staged service group is missing: $group"
    chown "0:$group_id" "$target"
  fi
}

install_unit() {
  source=$asset_root/$unit
  [ -f "$source" ] || die "service unit is missing: $source"
  install -d -m 0755 "$(root_path /etc/systemd/system)"
  unit_path=$(root_path "/etc/systemd/system/$unit")
	if [ "$provider" = holmes ] && [ -e "$unit_path" ] && ! grep -Fq 'Boetticher Holmes on-demand sandbox' "$unit_path"; then
	  die "refusing to replace an unowned existing unit: $unit_path"
	fi
	case "$provider" in
	  victoriametrics) sed "s/@RETENTION_DAYS@/$metrics_retention/g" "$source" > "$work/unit" ;;
	  victorialogs) sed "s/@RETENTION_DAYS@/$logs_retention/g" "$source" > "$work/unit" ;;
	  *) cp "$source" "$work/unit" ;;
	esac
	install_atomic 0644 "$work/unit" "$unit_path"
}

validate_local_assets() {
  if [ "$provider" != holmes ]; then
    [ -f "$asset_root/$unit" ] || die "service unit is missing: $asset_root/$unit"
  fi
  case "$provider" in
    grafana)
      [ -f "$asset_root/grafana-datasource.yaml" ] || die 'Grafana datasource provisioning asset is missing'
      [ -f "$asset_root/grafana-dashboard.yaml" ] || die 'Grafana dashboard provisioning asset is missing'
      [ -f "$asset_root/grafana-overview.json" ] || die 'Grafana overview dashboard asset is missing'
      [ -f "$asset_root/grafana-host-resources.json" ] || die 'Grafana host resources dashboard asset is missing'
      [ -f "$asset_root/grafana-service-logs.json" ] || die 'Grafana service logs dashboard asset is missing'
      [ -f "$asset_root/grafana-observability-health.json" ] || die 'Grafana observability health dashboard asset is missing'
      [ -f "$asset_root/grafana-alerting.yaml" ] || die 'Grafana alerting provisioning asset is missing'
      ;;
    gatus)
      gatus_source=${BOETTICHER_OBSERVABILITY_GATUS_BINARY:-$asset_root/../bin/gatus}
      [ -x "$gatus_source" ] || die "packaged Gatus binary is missing: $gatus_source"
      [ -f "$asset_root/gatus.config.yaml" ] || die 'Gatus configuration asset is missing'
      ;;
    bifrost)
      bifrost_source=${BOETTICHER_OBSERVABILITY_BIFROST_BINARY:-$asset_root/../bin/bifrost}
      [ -x "$bifrost_source" ] || die "packaged Bifrost binary is missing: $bifrost_source"
      bifrost_config=${BOETTICHER_OBSERVABILITY_BIFROST_CONFIG:-$asset_root/bifrost.config.json}
      [ -f "$bifrost_config" ] || die "Bifrost configuration asset is missing: $bifrost_config"
      validate_bifrost_credentials
      ;;
    holmes)
      [ -f "$holmes_root/holmes-runner.py" ] || die 'Holmes runner asset is missing'
      [ -f "$holmes_root/holmes.yaml" ] || die 'Holmes configuration asset is missing'
      [ -f "$holmes_lock" ] || die 'Holmes requirements lock is missing'
      ;;
  esac
}

validate_bifrost_credentials() {
  [ -f "${bifrost_config-}" ] || die 'Bifrost configuration is missing before credential validation'
  jq -er '.upstreams | if type == "array" and length > 0 then .[] | .credential else error("upstream credential list is empty") end' "$bifrost_config" > "$work/bifrost-credentials" || die 'Bifrost configuration has no valid upstream credentials'
  while IFS= read -r credential; do
    case "$credential" in
      ''|*[!A-Za-z0-9._-]*) die 'Bifrost configuration contains an invalid upstream credential name' ;;
    esac
    [ -s "$(root_path "/var/lib/boetticher/credentials/$credential.cred")" ] || die "Bifrost upstream credential is missing: $credential"
  done < "$work/bifrost-credentials"
}

install_bifrost_credentials() {
  dropin_dir=$(root_path /etc/systemd/system/bifrost.service.d)
  dropin=$(root_path /etc/systemd/system/bifrost.service.d/boetticher-credentials.conf)
  if [ -e "$dropin" ] && ! grep -Fq 'Boetticher Bifrost credentials' "$dropin"; then
    die "refusing to replace an unowned Bifrost credential drop-in: $dropin"
  fi
  install -d -m 0755 "$dropin_dir"
  {
    printf '%s\n' '# Boetticher Bifrost credentials'
    printf '%s\n' '[Service]'
    while IFS= read -r credential; do
      printf 'LoadCredential=%s:/var/lib/boetticher/credentials/%s.cred\n' "$credential" "$credential"
    done < "$work/bifrost-credentials"
  } > "$work/bifrost-credentials.conf"
  install_atomic 0644 "$work/bifrost-credentials.conf" "$dropin"
}

install_grafana_files() {
  install_optional_pushover_dropin grafana.service
  install -d -m 0755 "$(root_path /etc/grafana/provisioning/datasources)" "$(root_path /etc/grafana/provisioning/dashboards)" "$(root_path /etc/grafana/provisioning/alerting)" "$(root_path /etc/grafana/dashboards)"
  install_atomic 0644 "$asset_root/grafana-datasource.yaml" "$(root_path /etc/grafana/provisioning/datasources/boetticher.yaml)"
  install_atomic 0644 "$asset_root/grafana-dashboard.yaml" "$(root_path /etc/grafana/provisioning/dashboards/boetticher.yaml)"
  install_atomic 0644 "$asset_root/grafana-overview.json" "$(root_path /etc/grafana/dashboards/boetticher-overview.json)"
	install_atomic 0644 "$asset_root/grafana-host-resources.json" "$(root_path /etc/grafana/dashboards/boetticher-host-resources.json)"
	install_atomic 0644 "$asset_root/grafana-service-logs.json" "$(root_path /etc/grafana/dashboards/boetticher-service-logs.json)"
	install_atomic 0644 "$asset_root/grafana-observability-health.json" "$(root_path /etc/grafana/dashboards/boetticher-observability-health.json)"
	if [ "$pushover_enabled" = true ]; then
	  [ -s "$(root_path /var/lib/boetticher/credentials/pushover-credentials.cred)" ] || die 'Pushover credentials are missing before Grafana activation'
	  awk '
	    /^deleteContactPoints:/ { skip=1; next }
	    skip && /^[A-Za-z]/ { skip=0 }
    skip { next }
    /^        title: / {
      print
      print "        notification_settings:"
      print "          receiver: boetticher-pushover"
      next
    }
    { print }
  ' "$asset_root/grafana-alerting.yaml" > "$work/grafana-alerting.yaml"
	  cat >> "$work/grafana-alerting.yaml" <<EOF
contactPoints:
  - orgId: 1
    name: boetticher-pushover
    receivers:
      - uid: boetticher-pushover
        type: pushover
        settings:
          priority: "$pushover_priority"
          userKey: \${BOETTICHER_PUSHOVER_USER}
          apiToken: \${BOETTICHER_PUSHOVER_TOKEN}
EOF
  install_atomic 0644 "$work/grafana-alerting.yaml" "$(root_path /etc/grafana/provisioning/alerting/boetticher.yaml)"
	else
	  install_atomic 0644 "$asset_root/grafana-alerting.yaml" "$(root_path /etc/grafana/provisioning/alerting/boetticher.yaml)"
	fi
	grafana_root_url=http://127.0.0.1:3000/
	[ -z "$public_domain" ] || grafana_root_url=https://observability.$public_domain/
	cat > "$work/boetticher-grafana.ini" <<EOF
[paths]
provisioning = /etc/grafana/provisioning
data = /var/lib/boetticher/observability/state/grafana/data
logs = /var/lib/boetticher/observability/state/grafana/logs
plugins = /var/lib/boetticher/observability/state/grafana/plugins
[server]
http_addr = 127.0.0.1
root_url = $grafana_root_url
[auth.anonymous]
enabled = false
EOF
	install_atomic 0644 "$work/boetticher-grafana.ini" "$(root_path /etc/grafana/grafana.ini)"
	install_owned_dir "$(root_path /var/lib/boetticher/observability/state/grafana/data)" grafana 0750
	install_owned_dir "$(root_path /var/lib/boetticher/observability/state/grafana/logs)" grafana 0750
	install_owned_dir "$(root_path /var/lib/boetticher/observability/state/grafana/plugins)" grafana 0750
}

install_optional_pushover_dropin() {
  service=$1
  dropin_dir=$(root_path "/etc/systemd/system/$service.d")
  dropin=$(root_path "/etc/systemd/system/$service.d/boetticher-pushover.conf")
  if [ "$pushover_enabled" = true ]; then
    [ -s "$(root_path /var/lib/boetticher/credentials/pushover-credentials.cred)" ] || die "Pushover credentials are missing before $service activation"
    install -d -m 0755 "$dropin_dir"
    printf '%s\n' '# Boetticher Pushover credentials' '[Service]' 'LoadCredential=pushover-credentials:/var/lib/boetticher/credentials/pushover-credentials.cred' > "$work/$service-pushover.conf"
    install_atomic 0644 "$work/$service-pushover.conf" "$dropin"
  elif [ -e "$dropin" ]; then
    grep -Fq 'Boetticher Pushover credentials' "$dropin" || die "refusing to remove an unowned Pushover drop-in: $dropin"
    rm -f "$dropin"
  fi
}

install_caddy_files() {
  caddy_source=${BOETTICHER_OBSERVABILITY_CADDY_BINARY:-$asset_root/../bin/caddy}
  metrics_controller=${BOETTICHER_OBSERVABILITY_METRICS_CONTROLLER:-}
  metrics_host=${BOETTICHER_OBSERVABILITY_METRICS_HOST:-}
  metrics_runtime=${BOETTICHER_OBSERVABILITY_METRICS_RUNTIME:-}
  ingest_sources=${BOETTICHER_OBSERVABILITY_INGEST_SOURCES:-}
  [ -x "$caddy_source" ] || die "packaged Caddy binary is missing: $caddy_source"
  [ -s "$(root_path /var/lib/boetticher/credentials/cloudflare-dns-token.cred)" ] || die 'Cloudflare DNS credential is missing before Caddy activation'
  [ -s "$(root_path /var/lib/boetticher/credentials/statuspage-password.cred)" ] || die 'status page password credential is missing before Caddy activation'
  for address in "$metrics_controller" "$metrics_host" "$metrics_runtime"; do
    case "$address" in ''|*[!0-9.]*) die 'Caddy metrics target address is invalid' ;; esac
    printf '%s\n' "$address" | awk -F. 'NF == 4 { for (i = 1; i <= 4; i++) if ($i < 0 || $i > 255) exit 1; exit 0 } { exit 1 }' || die 'Caddy metrics target address is invalid'
  done
  [ -n "$ingest_sources" ] || die 'Caddy ingest source allowlist is missing'
  for address in $ingest_sources; do
    case "$address" in ''|*[!0-9.]*) die 'Caddy ingest source address is invalid' ;; esac
    printf '%s\n' "$address" | awk -F. 'NF == 4 { for (i = 1; i <= 4; i++) if ($i < 0 || $i > 255) exit 1; exit 0 } { exit 1 }' || die 'Caddy ingest source address is invalid'
  done
  install_atomic 0755 "$caddy_source" "$(root_path /usr/local/bin/caddy)"
  install -d -m 0750 "$(root_path /etc/boetticher/caddy)"
  chown_root_group "$(root_path /etc/boetticher/caddy)" caddy
  cat > "$work/Caddyfile" <<EOF
{
  admin unix//run/caddy/admin.sock
  auto_https disable_redirects
  storage file_system {
    root /var/lib/boetticher/observability/state/caddy
  }
}

https://observability.$public_domain {
  bind 10.10.10.20
  tls {
    dns cloudflare {env.CLOUDFLARE_API_TOKEN}
    # ACME validates DNS independently; skip only blocked local propagation polling.
    propagation_delay 30s
    propagation_timeout -1
  }
  reverse_proxy 127.0.0.1:3000
}

https://status.$public_domain {
  bind 10.10.10.20
  tls {
    dns cloudflare {env.CLOUDFLARE_API_TOKEN}
    propagation_delay 30s
    propagation_timeout -1
  }
  basic_auth {
    status {\$BOETTICHER_STATUS_PASSWORD_HASH}
  }
  reverse_proxy 127.0.0.1:8080
}

https://metrics.$public_domain {
  bind 10.10.10.20
  tls {
    dns cloudflare {env.CLOUDFLARE_API_TOKEN}
    propagation_delay 30s
    propagation_timeout -1
  }
  basic_auth {
    boetticher {\$BOETTICHER_METRICS_PASSWORD_HASH}
  }
  @controller {
    path /controller/metrics
    remote_ip 10.10.10.20
  }
  handle @controller {
    uri strip_prefix /controller
    reverse_proxy $metrics_controller:9100 {
      header_up Host $metrics_controller
      header_up Authorization "Basic {env.BOETTICHER_NODE_EXPORTER_AUTH}"
    }
  }
  @proxmox {
    path /proxmox-host/metrics
    remote_ip 10.10.10.20
  }
  handle @proxmox {
    uri strip_prefix /proxmox-host
    reverse_proxy $metrics_host:9100 {
      header_up Host $metrics_host
      header_up Authorization "Basic {env.BOETTICHER_NODE_EXPORTER_AUTH}"
    }
  }
  @runtime {
    path /lab-monitor-01/metrics
    remote_ip 10.10.10.20
  }
  handle @runtime {
    uri strip_prefix /lab-monitor-01
    reverse_proxy $metrics_runtime:9100 {
      header_up Host $metrics_runtime
      header_up Authorization "Basic {env.BOETTICHER_NODE_EXPORTER_AUTH}"
    }
  }
  respond 404
}

https://ingest.$public_domain {
  bind 10.10.10.20
  tls {
    dns cloudflare {env.CLOUDFLARE_API_TOKEN}
    propagation_delay 30s
    propagation_timeout -1
  }
  @journald {
    method POST
    path /upload
    remote_ip $ingest_sources
  }
  handle @journald {
    rewrite * /insert/journald/upload
    reverse_proxy 127.0.0.1:9428
  }
  respond 403
}
EOF
  target=$(root_path /etc/boetticher/caddy/Caddyfile)
  if [ "$root" = / ]; then
    status_hash=$({ cat /var/lib/boetticher/credentials/statuspage-password.cred; printf '\n'; } | "$caddy_source" hash-password --algorithm bcrypt) || die 'Caddy status password hash generation failed'
    node_hash=$({ cat /var/lib/boetticher/credentials/node-exporter-read-token.cred; printf '\n'; } | "$caddy_source" hash-password --algorithm bcrypt) || die 'Caddy metrics password hash generation failed'
    CLOUDFLARE_API_TOKEN=$(cat /var/lib/boetticher/credentials/cloudflare-dns-token.cred) BOETTICHER_STATUS_PASSWORD_HASH="$status_hash" BOETTICHER_METRICS_PASSWORD_HASH="$node_hash" "$caddy_source" validate --config "$work/Caddyfile" --adapter caddyfile >/dev/null || die 'Caddy configuration validation failed'
    unset status_hash node_hash
  fi
  previous="$work/Caddyfile.previous"
  if [ -f "$target" ]; then
    install -m 0640 "$target" "$previous"
  fi
  install_atomic 0640 "$work/Caddyfile" "$target"
  chown_root_group "$target" caddy
  if [ "$root" = / ] && systemctl is-active --quiet caddy.service; then
    if ! systemctl reload caddy.service; then
      if [ -f "$previous" ]; then
        install_atomic 0640 "$previous" "$target"
        chown_root_group "$target" caddy
        systemctl reload caddy.service || true
      fi
      die 'Caddy configuration reload failed; previous configuration restored'
    fi
  fi
  install_owned_dir "$(root_path /var/lib/boetticher/observability/state/caddy)" caddy 0750
}

install_grafana_plugin() {
  plugin_archive=$work/victorialogs-datasource.zip
  download_verified victorialogs-datasource "$plugin_archive"
  plugin_root=$work/grafana-plugin
  mkdir -p "$plugin_root"
  python3 - "$plugin_archive" "$plugin_root" <<'PY'
import os
import pathlib
import stat
import sys
import zipfile

archive, destination = sys.argv[1:]
root = pathlib.Path(destination).resolve()
with zipfile.ZipFile(archive) as bundle:
    for info in bundle.infolist():
        raw = info.filename
        if not raw or "\\" in raw or "\x00" in raw:
            raise SystemExit(f"unsafe plugin member: {raw!r}")
        path = pathlib.PurePosixPath(raw)
        if path.is_absolute() or ".." in path.parts or any(part == "." for part in path.parts):
            raise SystemExit(f"unsafe plugin member: {raw!r}")
        mode = (info.external_attr >> 16) & 0o170000
        if mode in (stat.S_IFLNK, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO):
            raise SystemExit(f"unsupported plugin member: {raw!r}")
        target = (root / pathlib.Path(*path.parts)).resolve()
        if root not in target.parents and target != root:
            raise SystemExit(f"plugin member escapes destination: {raw!r}")
        if info.is_dir() or raw.endswith('/'):
            target.mkdir(mode=0o755, parents=True, exist_ok=True)
            continue
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        mode_bits = (info.external_attr >> 16) & 0o7777
        mode_bits = mode_bits or 0o644
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode_bits)
        with os.fdopen(fd, 'wb') as output:
            output.write(bundle.read(info))
        os.chmod(target, mode_bits)
PY
  plugin_dir=$(find "$plugin_root" -type f -name plugin.json -print | head -n 1 | sed 's#/plugin.json$##')
  [ -n "$plugin_dir" ] || die 'VictoriaLogs datasource plugin has no plugin.json'
  plugin_parent=$(root_path /var/lib/boetticher/observability/state/grafana/plugins)
  install_owned_dir "$plugin_parent" grafana 0750
  plugin_stage="$plugin_parent/.victoriametrics-logs-datasource.new.$$"
  plugin_target="$plugin_parent/victoriametrics-logs-datasource"
  plugin_old="$plugin_parent/.victoriametrics-logs-datasource.old.$$"
  rm -rf "$plugin_stage" "$plugin_old"
  cp -R "$plugin_dir" "$plugin_stage"
  chown_owned "$plugin_stage" grafana
  if [ "$root" = / ]; then
    chown -R grafana:grafana "$plugin_stage"
  else
    owner_id=$(awk -F: -v account=grafana '$1 == account { print $3 ":" $4; exit }' "$(root_path /etc/passwd)")
    [ -n "$owner_id" ] || die 'staged Grafana account is missing'
    chown -R "$owner_id" "$plugin_stage"
  fi
  if [ -e "$plugin_target" ] || [ -L "$plugin_target" ]; then
    mv "$plugin_target" "$plugin_old" || die 'cannot stage the existing Grafana plugin for replacement'
    if ! mv "$plugin_stage" "$plugin_target"; then
      mv "$plugin_old" "$plugin_target" || die 'cannot restore the existing Grafana plugin'
      die 'cannot activate the staged Grafana plugin'
    fi
    rm -rf "$plugin_old"
  else
    mv "$plugin_stage" "$plugin_target" || die 'cannot activate the staged Grafana plugin'
  fi
}

case "$root" in
  /) cache=${BOETTICHER_OBSERVABILITY_CACHE:-/var/cache/boetticher/observability} ;;
  *) cache=${BOETTICHER_OBSERVABILITY_CACHE:-$root/var/cache/boetticher/observability} ;;
esac
install -d -m 0750 "$cache"
work=$(mktemp -d "$cache/.install-$provider.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
validate_local_assets

# Download and validate all provider bytes before changing any installed file.
case "$provider" in
  victorialogs|victoriametrics|grafana) download_verified "$provider" "$work/$archive_name" ;;
esac

ensure_account "$user" "/var/lib/$user"
install_owned_dir "$(root_path "$data_dir")" "$user" 0750

case "$provider" in
  victorialogs)
    extract_tar_binary "$work/$archive_name" victoria-logs-prod "$work/victoria-logs"
    install_atomic 0755 "$work/victoria-logs.ready" "$(root_path /usr/local/bin/victoria-logs)"
    ;;
  victoriametrics)
    extract_tar_binary "$work/$archive_name" victoria-metrics-prod "$work/victoria-metrics"
    install_atomic 0755 "$work/victoria-metrics.ready" "$(root_path /usr/local/bin/victoria-metrics)"
    ;;
  grafana)
    [ -f "$work/$archive_name" ] || die 'Grafana package was not staged'
    if [ "$root" = / ]; then
      dpkg --install "$work/$archive_name" || die 'Grafana package installation failed'
    else
      dpkg --root="$root" --install "$work/$archive_name" || die 'staged Grafana package installation failed'
    fi
    # The Debian package may enable grafana-server.service. The managed unit
    # owns the sole loopback listener and the package unit must stay disabled
    # across reinstall and reapply.
    if [ "$root" = / ]; then
      systemctl disable --now grafana-server.service || true
    else
      systemctl --root="$root" disable grafana-server.service || true
    fi
    install_grafana_plugin
    install_grafana_files
    ;;
  gatus)
    gatus_source=${BOETTICHER_OBSERVABILITY_GATUS_BINARY:-$asset_root/../bin/gatus}
    [ -x "$gatus_source" ] || die "packaged Gatus binary is missing: $gatus_source"
    install_atomic 0755 "$gatus_source" "$(root_path /usr/local/bin/gatus)"
    [ -f "$asset_root/gatus.config.yaml" ] || die 'Gatus configuration asset is missing'
    install_optional_pushover_dropin gatus.service
    install -d -m 0750 "$(root_path /etc/boetticher/gatus)"
    chown_owned "$(root_path /etc/boetticher/gatus)" gatus
    gatus_config_source=$asset_root/gatus.config.yaml
    if [ -n "$public_domain" ]; then
      metrics_controller=${BOETTICHER_OBSERVABILITY_METRICS_CONTROLLER:-}
      metrics_host=${BOETTICHER_OBSERVABILITY_METRICS_HOST:-}
      [ -n "$metrics_controller" ] && [ -n "$metrics_host" ] || die 'Gatus collection outcome addresses are missing'
      awk -v domain="$public_domain" -v controller="$metrics_controller" -v host="$metrics_host" '
        /^endpoints:/ {
          print
          print "  - name: dns-observability"
          print "    group: collection"
          print "    url: 10.10.10.1"
          print "    interval: 30s"
          print "    dns:"
          print "      query-name: observability." domain
          print "      query-type: A"
          print "    conditions:"
          print "      - \"[BODY] == 10.10.10.20\""
          print "      - \"[DNS_RCODE] == NOERROR\""
          print "  - name: tcp-proxmox-node-exporter"
          print "    group: collection"
          print "    url: tcp://" host ":9100"
          print "    interval: 30s"
          print "    conditions:"
          print "      - \"[CONNECTED] == true\""
          print "  - name: tcp-controller-node-exporter"
          print "    group: collection"
          print "    url: tcp://" controller ":9100"
          print "    interval: 30s"
          print "    conditions:"
          print "      - \"[CONNECTED] == true\""
          print "  - name: caddy-observability"
          print "    group: observability"
          print "    url: https://observability." domain "/api/health"
          print "    interval: 30s"
          print "    conditions:"
          print "      - \"[STATUS] == 200\""
          print "  - name: caddy-status"
          print "    group: observability"
          print "    url: https://status." domain "/health"
          print "    interval: 30s"
          print "    conditions:"
          print "      - \"[STATUS] == 401\""
          print "  - name: caddy-metrics"
          print "    group: observability"
          print "    url: https://metrics." domain "/lab-monitor-01/metrics"
          print "    interval: 30s"
          print "    conditions:"
          print "      - \"[STATUS] == 401\""
          next
        }
        { print }
      ' "$asset_root/gatus.config.yaml" > "$work/gatus-public.config.yaml"
      gatus_config_source=$work/gatus-public.config.yaml
    fi
    if [ "$pushover_enabled" = true ]; then
      awk '
        /^      - \"\[STATUS\] == 200\"$/ {
          print
          print "    alerts:"
          print "      - type: pushover"
          print "        failure-threshold: 3"
          print "        success-threshold: 2"
          print "        send-on-resolved: false"
          print "        description: \"Boetticher observability endpoint health check\""
          next
        }
        { print }
      ' "$gatus_config_source" > "$work/gatus.config.yaml"
      cat >> "$work/gatus.config.yaml" <<EOF
alerting:
  pushover:
    application-token: \${BOETTICHER_PUSHOVER_TOKEN}
    user-key: \${BOETTICHER_PUSHOVER_USER}
    title: "$pushover_title"
    priority: $pushover_priority
    resolved-priority: 0
EOF
      install_atomic 0640 "$work/gatus.config.yaml" "$(root_path /etc/boetticher/gatus/config.yaml)"
    else
      install_atomic 0640 "$gatus_config_source" "$(root_path /etc/boetticher/gatus/config.yaml)"
    fi
    chown_owned "$(root_path /etc/boetticher/gatus/config.yaml)" gatus
    ;;
  caddy)
    install_caddy_files
    ;;
  bifrost)
    install_atomic 0755 "$bifrost_source" "$(root_path /usr/local/libexec/boetticher-bifrost)"
    install -d -m 0750 "$(root_path /etc/boetticher/bifrost)"
    chown_root_group "$(root_path /etc/boetticher/bifrost)" bifrost
    install_atomic 0640 "$bifrost_config" "$(root_path /etc/boetticher/bifrost/config.json)"
    chown_root_group "$(root_path /etc/boetticher/bifrost/config.json)" bifrost
    install_bifrost_credentials
    ;;
  holmes)
    install -d -m 0750 "$(root_path /opt/boetticher/observability/holmes)" "$(root_path /etc/boetticher/holmes)"
    install_owned_dir "$(root_path /opt/boetticher/observability/holmes)" holmes 0750
    install_atomic 0644 "$holmes_root/holmes-runner.py" "$(root_path /opt/boetticher/observability/holmes/holmes-runner.py)"
    install_atomic 0644 "$holmes_root/holmes.yaml" "$(root_path /etc/boetticher/holmes/config.yaml)"
    install_atomic 0644 "$holmes_lock" "$(root_path /opt/boetticher/observability/holmes/requirements.lock)"
    if [ "$root" = / ]; then
      uv_archive=$work/uv.tar.gz
      download_verified uv-x86_64-linux "$uv_archive"
      extract_tar_binary "$uv_archive" uv "$work/uv"
      install_atomic 0755 "$work/uv.ready" /usr/local/bin/boetticher-uv
      /usr/local/bin/boetticher-uv venv --python /usr/bin/python3 /opt/boetticher/observability/holmes/venv || die 'Holmes virtual environment creation failed'
      /usr/local/bin/boetticher-uv pip sync --require-hashes --python /opt/boetticher/observability/holmes/venv/bin/python /opt/boetticher/observability/holmes/requirements.lock || die 'Holmes locked dependency installation failed'
    fi
    ;;
esac

if [ "$provider" != holmes ]; then
  install_unit
fi
if [ -n "$config_digest" ]; then
  digest_path=$(root_path "$data_dir/boetticher-config.digest")
  printf '%s\n' "$config_digest" > "$work/digest"
  install_atomic 0640 "$work/digest" "$digest_path"
  chown_owned "$digest_path" "$user"
fi
if [ "$root" = / ]; then
  if [ "$provider" != holmes ]; then
    systemctl daemon-reload
    systemctl enable "$unit"
    systemctl restart "$unit"
    systemctl is-active --quiet "$unit" || die "$unit did not become active"
  fi
  case "$provider" in
    victorialogs) wait_for_local_http http://127.0.0.1:9428/health ;;
    victoriametrics) wait_for_local_http http://127.0.0.1:8428/health ;;
    grafana) wait_for_local_http http://127.0.0.1:3000/api/health ;;
    gatus) wait_for_local_http http://127.0.0.1:8080/health ;;
    bifrost) wait_for_local_http http://127.0.0.1:4000/health ;;
  esac
  if [ "$provider" = holmes ]; then
    printf 'provider %s: PASS (installed; on-demand health NOT TESTED)\n' "$provider"
  else
    printf 'provider %s: PASS (installed, enabled, and health checked)\n' "$provider"
  fi
else
  if [ "$provider" != holmes ]; then
    systemctl --root="$root" enable "$unit"
  fi
  if [ "$provider" = holmes ]; then
    printf 'provider %s: PASS (staged; on-demand health NOT TESTED)\n' "$provider"
  else
    printf 'provider %s: PASS (staged and enabled; health NOT TESTED)\n' "$provider"
  fi
fi
