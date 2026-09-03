#!/bin/sh
set -eu

# Linux-native appliance construction. The builder VM and a Linux controller
# execute this same script; macOS controllers intentionally stop before any
# image tooling is attempted.
target=${1:-images}
shift || true
case "$target" in
  image-base|image-dns-blocky|image-logging|image-monitoring|image-portal|image-firewall|image-tailnet-router|image-bifrost|image-aiops|image-printer|image-arr|image-gatus|image-network-probe|images) ;;
  image-airvpn) ;;
  *) echo "unknown image target: $target" >&2; exit 2 ;;
esac

default_image_targets="image-base image-dns-blocky image-logging image-monitoring image-portal image-tailnet-router image-airvpn image-bifrost image-printer image-arr image-aiops image-gatus image-network-probe image-firewall"
if [ "$target" = images ]; then
  selected_image_targets="$*"
  if [ -z "$selected_image_targets" ]; then
    selected_image_targets=$default_image_targets
  fi
  for selected_target in $selected_image_targets; do
    case "$selected_target" in
      image-base|image-dns-blocky|image-logging|image-monitoring|image-portal|image-firewall|image-tailnet-router|image-bifrost|image-aiops|image-printer|image-arr|image-gatus|image-network-probe) ;;
      image-airvpn) ;;
      *) echo "unknown selected image target: $selected_target" >&2; exit 2 ;;
    esac
  done
else
  selected_image_targets=$target
fi

if [ "$(uname -s)" != Linux ]; then
  echo "HOLD: appliance construction requires the supported Linux builder environment; use boetticher bootstrap on macOS" >&2
  exit 2
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "HOLD: appliance construction requires root in the supported Linux builder environment for mmdebstrap/chroot/mount operations" >&2
  exit 2
fi

# Use the Go toolchain supplied by the pinned Debian builder image. Automatic
# toolchain downloads would make appliance construction depend on an
# unqualified network input.
export GOTOOLCHAIN=local

timing_now_ms() {
  date +%s%3N
}

timing_emit() {
  stage=$1
  duration_ms=$2
  artifact=${3:-}
  line="timing stage=$stage duration_ms=$duration_ms"
  if [ -n "$artifact" ]; then
    line="$line artifact=$artifact"
  fi
  printf '%s\n' "$line"
  if [ -n "${timing_log:-}" ]; then
    printf '%s\n' "$line" >> "$timing_log"
  fi
}

measurement_emit() {
  measurement_stage=$1
  shift
  measurement_line="measurement stage=$measurement_stage"
  for measurement_field in "$@"; do
    measurement_line="$measurement_line $measurement_field"
  done
  printf '%s\n' "$measurement_line"
  if [ -n "${timing_log:-}" ]; then
    printf '%s\n' "$measurement_line" >> "$timing_log"
  fi
}

verify_cached() {
  cache_expected=$1
  cache_file=$2
  cache_checker=$3
  case "$cache_checker" in
    sha256sum) printf '%s  %s\n' "$cache_expected" "$cache_file" | sha256sum --check --status ;;
    sha512sum) printf '%s  %s\n' "$cache_expected" "$cache_file" | sha512sum --check --status ;;
    *) echo "HOLD: unsupported cached download checksum tool: $cache_checker" >&2; return 2 ;;
  esac
}

download_cached() {
  cache_destination=$1
  cache_url=$2
  cache_expected=$3
  cache_checker=$4
  mkdir -p "$(dirname "$cache_destination")"
  if [ ! -f "$cache_destination" ]; then
    cache_temporary="$cache_destination.tmp.$$"
    rm -f "$cache_temporary"
    curl --fail --location --silent --show-error --output "$cache_temporary" "$cache_url"
    if ! verify_cached "$cache_expected" "$cache_temporary" "$cache_checker"; then
      rm -f "$cache_temporary"
      return 1
    fi
    mv "$cache_temporary" "$cache_destination"
  else
    verify_cached "$cache_expected" "$cache_destination" "$cache_checker"
  fi
}

# Level 3 keeps the qualified artifact format and integrity checks while
# avoiding the disproportionate CPU cost of the historical level-19 default.
# The environment override remains available for measured release trials.
zstd_level=${BOETTICHER_ZSTD_LEVEL:-3}
case "$zstd_level" in
  ''|*[!0-9]*)
    echo "HOLD: BOETTICHER_ZSTD_LEVEL must be an integer from 1 through 22" >&2
    exit 2
    ;;
esac
if [ "$zstd_level" -lt 1 ] || [ "$zstd_level" -gt 22 ]; then
  echo "HOLD: BOETTICHER_ZSTD_LEVEL must be an integer from 1 through 22" >&2
  exit 2
fi

for tool in mmdebstrap tar zstd sha256sum curl chroot go jq stat du find wc awk tr; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "HOLD: required Linux image-build tool is unavailable: $tool" >&2
    exit 2
  fi
done
if [ ! -x /usr/bin/time ]; then
  echo "HOLD: required Linux image-build tool is unavailable: /usr/bin/time" >&2
  exit 2
fi

output_root=${BOETTICHER_ARTIFACT_OUTPUT:-generated/artifacts}
work_root=${BOETTICHER_IMAGE_WORK:-/tmp/boetticher-image-build}
cache_root=${BOETTICHER_CACHE_ROOT:-$work_root/cache}
timing_log=${BOETTICHER_TIMING_LOG:-}
script_path=$0
base_definition=images/base/debian.yaml
base_release=$(sed -n 's/^release: *//p' "$base_definition")
mirror=$(sed -n 's/^  mirror: *//p' "$base_definition")
base_packages=$(awk '
  /^build:$/ { in_build=1; next }
  in_build && /^  packages:$/ { in_packages=1; next }
  in_packages && /^    - / { sub(/^    - /, ""); printf "%s%s", separator, $0; separator=","; next }
  in_packages && !/^    - / { exit }
' "$base_definition")
if [ -z "$base_release" ] || [ -z "$mirror" ] || [ -z "$base_packages" ]; then
  echo "HOLD: base image definition is missing its pinned release, mirror, or build package contract" >&2
  exit 2
fi
powerdns_key_url=https://repo.powerdns.com/FD380FBB-pub.asc
powerdns_key_sha256=efeb5b1451c76de1dac8eefaddba5af5549e8fd93484728744ea7b4923decae8
powerdns_repo=https://repo.powerdns.com/debian
powerdns_suite=trixie-auth-49
powerdns_package_version=4.9.17-1pdns.trixie
pulse_version=6.1.2
pulse_release_url=https://github.com/rcourtman/Pulse/releases/download/v6.1.2/pulse-v6.1.2-linux-amd64.tar.gz
pulse_release_sha256=844cd054bcfce528cbcf434d782e571791cc7b02ef2fe298cf138b1cab1087ea
tailscale_package_version=1.76.6
tailscale_key_url=https://pkgs.tailscale.com/stable/debian/trixie.noarmor.gpg
tailscale_key_sha256=3e03dacf222698c60b8e2f990b809ca1b3e104de127767864284e6c228f1fb39
tailscale_keyring=/usr/share/keyrings/tailscale-archive-keyring.gpg
aiops_python_package_version=3.13.5-1
aiops_python_venv_package_version=3.13.5-1
aiops_pip_package_version=25.1.1+dfsg-1
bifrost_nginx_package_version=1.26.3-3+deb13u7
holmes_source_url=https://codeload.github.com/HolmesGPT/holmesgpt/tar.gz/3d201559c0f3648a6c567aece09662f4f407bcc9
holmes_source_sha256=7016d3335a7f81810de35d9030a63bc38204d94991e3343d6cdbbcaf77a755be
holmes_source_root=holmesgpt-3d201559c0f3648a6c567aece09662f4f407bcc9
gatus_source_url=https://github.com/TwiN/gatus/archive/refs/tags/v5.36.0.tar.gz
gatus_source_sha256=b5543af591e602281406049ee2f822a6529a8f14be0cd54df5a31c210520159a
arr_nginx_package_version=1.26.3-3+deb13u7
sonarr_version=4.0.19.2979
sonarr_release_url=https://github.com/Sonarr/Sonarr/releases/download/v4.0.19.2979/Sonarr.main.4.0.19.2979.linux-x64.tar.gz
sonarr_release_sha256=b691b3584c31c0b5514058dee81071c923f63d59a37d19e32f92fa13eaa153db
radarr_version=6.3.0.10514
radarr_release_url=https://github.com/Radarr/Radarr/releases/download/v6.3.0.10514/Radarr.master.6.3.0.10514.linux-core-x64.tar.gz
radarr_release_sha256=41d6455c037ff267c5ad5a0f0de4502cebe8f89ec3d051da97851933d48a4047
mkdir -p "$output_root" "$work_root" "$cache_root/apt" "$cache_root/downloads" "$cache_root/base"

provenance_path="$(dirname "$output_root")/builder-provenance.json"
version_or_unavailable() {
  tool=$1
  if command -v "$tool" >/dev/null 2>&1; then
    "$tool" --version 2>&1 | head -n 1
  else
    printf '%s\n' unavailable
  fi
}

write_builder_provenance() {
  jq -n \
    --arg platform debian-13-amd64 \
    --arg input_image debian-13-genericcloud-amd64-20260327-2429 \
    --arg kernel "$(uname -r)" \
    --arg go "$(go version)" \
    --arg trivy "$(version_or_unavailable trivy)" \
    --arg mmdebstrap "$(version_or_unavailable mmdebstrap)" \
    --arg libguestfs "$(version_or_unavailable guestfish)" \
    --arg qemu_img "$(version_or_unavailable qemu-img)" \
    --arg architecture amd64 \
    --arg boetticher_version "${BOETTICHER_RELEASE_VERSION:-0.5.0}" \
    '{platform:$platform,input_image:$input_image,kernel:$kernel,go:$go,trivy:$trivy,mmdebstrap:$mmdebstrap,libguestfs:$libguestfs,qemu_img:$qemu_img,architecture:$architecture,boetticher_version:$boetticher_version}' \
    > "$provenance_path"
  chmod 0644 "$provenance_path"
}

if [ "${BOETTICHER_SKIP_PROVENANCE:-0}" != 1 ]; then
  write_builder_provenance
fi

cleanup() {
  if [ -n "${ACTIVE_ROOT:-}" ] && [ -d "$ACTIVE_ROOT" ]; then
    umount -R "$ACTIVE_ROOT/dev" 2>/dev/null || true
    umount -R "$ACTIVE_ROOT/proc" 2>/dev/null || true
    umount -R "$ACTIVE_ROOT/sys" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

rootfs_for() {
  if [ "$1" = boetticher-base ]; then
    printf '%s\n' "${BOETTICHER_BASE_ROOTFS:-$work_root/boetticher-base-rootfs}"
  else
    printf '%s/%s-rootfs\n' "$work_root" "$1"
  fi
}

artifact_for() {
	name=$1
	version=1.0.0
	if [ "$name" = boetticher-base ]; then
		version=0.5.0
	fi
	printf '%s/%s/%s-%s-amd64.tar.zst' "$output_root" "$name" "$name" "$version"
}

create_base_rootfs() {
  rootfs=$1
  base_inputs_digest=$(sha256sum "$base_definition" images/base/runtime/* images/base/first-boot/* "$script_path" | sha256sum | awk '{print $1}')
  base_cache_key=$(printf '%s\n' "$base_release" "$mirror" "$base_packages" "$base_inputs_digest" | sha256sum | awk '{print $1}')
  base_cache="$cache_root/base/$base_cache_key"
  if [ -f "$base_cache/.boetticher-base-complete" ] && [ -d "$base_cache/etc" ]; then
    rm -rf "$rootfs"
    mkdir -p "$rootfs"
    cp -a --reflink=auto "$base_cache/." "$rootfs/"
    rm -f "$rootfs/.boetticher-base-complete"
    measurement_emit "build_cache" "kind=base" "status=hit" "key=$base_cache_key"
    return
  fi
  rm -rf "$rootfs"
  mkdir -p "$rootfs"
  mmdebstrap --variant=minbase --architectures=amd64 \
    --aptopt=Acquire::Check-Valid-Until=false \
    --aptopt=Acquire::Languages=none \
    --include="$base_packages" \
    "$base_release" "$rootfs" "$mirror"
  install -D -m 0644 images/base/runtime/debian-security-snapshot.sources "$rootfs/etc/apt/sources.list.d/boetticher-debian-security.sources"
  mkdir -p "$rootfs/etc/boetticher" "$rootfs/usr/lib/boetticher" "$rootfs/run/boetticher/bootstrap"
  install -D -m 0644 images/base/runtime/journal-upload.conf "$rootfs/etc/systemd/journal-upload.conf"
  install -D -m 0440 images/base/runtime/boetticher.sudoers "$rootfs/etc/sudoers.d/boetticher"
  chroot "$rootfs" chown root:root /etc/sudoers.d/boetticher
  install -D -m 0755 images/base/first-boot/boetticher-first-boot.sh "$rootfs/usr/lib/boetticher/boetticher-first-boot.sh"
  install -D -m 0644 images/base/first-boot/boetticher-first-boot.service "$rootfs/etc/systemd/system/boetticher-first-boot.service"
  install -D -m 0755 images/base/runtime/install-runtime-state.sh "$rootfs/usr/lib/boetticher/install-runtime-state"
  chroot "$rootfs" useradd --create-home --shell /bin/bash labadmin
  chroot "$rootfs" passwd --lock labadmin
  mkdir -p "$rootfs/tmp/boetticher-ansible"
  chroot "$rootfs" chown labadmin:labadmin /tmp/boetticher-ansible
  chmod 0700 "$rootfs/tmp/boetticher-ansible"
  chroot "$rootfs" visudo -cf /etc/sudoers
  mkdir -p "$rootfs/etc/systemd/journald.conf.d"
  printf '%s\n' '[Journal]' 'SystemMaxUse=256M' 'RuntimeMaxUse=64M' > "$rootfs/etc/systemd/journald.conf.d/boetticher.conf"
  install -D -m 0644 images/base/runtime/sshd.conf "$rootfs/etc/ssh/sshd_config.d/boetticher.conf"
  install -D -m 0644 images/base/runtime/sshd-host-key.conf "$rootfs/etc/ssh/sshd_config.d/boetticher-host-key.conf"
  # Host keys are endpoint identity and must be generated after deployment.
  rm -f "$rootfs"/etc/ssh/ssh_host_*
  rm -f "$rootfs/root/.ssh/authorized_keys" "$rootfs/home/labadmin/.ssh/authorized_keys"
  rm -f "$rootfs/etc/ssl/private/ssl-cert-snakeoil.key"
  chroot "$rootfs" systemctl enable boetticher-first-boot.service
  cache_tmp="$cache_root/base/.${base_cache_key}.tmp.$$"
  rm -rf "$cache_tmp"
  mkdir -p "$cache_tmp"
  cp -a --reflink=auto "$rootfs/." "$cache_tmp/"
  touch "$cache_tmp/.boetticher-base-complete"
  rm -rf "$base_cache"
  mv "$cache_tmp" "$base_cache"
  measurement_emit "build_cache" "kind=base" "status=stored" "key=$base_cache_key"
}

write_artifact_identity() {
  rootfs=$1
  module=$2
  go run ./cmd/artifact-identity -module "$module" > "$rootfs/usr/lib/boetticher/artifact.json"
  chmod 0644 "$rootfs/usr/lib/boetticher/artifact.json"
}

prepare_rootfs() {
  name=$1
  rootfs=$(rootfs_for "$name")
  if [ ! -d "$(rootfs_for boetticher-base)/etc" ]; then
    create_base_rootfs "$(rootfs_for boetticher-base)"
  fi
  rm -rf "$rootfs"
  cp -a --reflink=auto "$(rootfs_for boetticher-base)" "$rootfs"
  ACTIVE_ROOT=$rootfs
  mkdir -p "$rootfs/var/lib/boetticher/identity/ssh" "$rootfs/etc/boetticher" "$rootfs/usr/lib/boetticher"
  printf '%s\n' "artifact=$name" > "$rootfs/usr/lib/boetticher/build-input.txt"
  printf '%s\n' "$rootfs"
}

pip_install() {
  rootfs=$1
  pip_path=$2
  shift 2
  pip_cache="$cache_root/pip"
  mkdir -p "$pip_cache" "$rootfs/root/.cache/pip"
  mount --bind "$pip_cache" "$rootfs/root/.cache/pip"
  if chroot "$rootfs" "$pip_path" "$@"; then
    status=0
  else
    status=$?
  fi
  umount -R "$rootfs/root/.cache/pip" || true
  return "$status"
}

install_packages() {
  rootfs=$1
  shift
  package_cache="$cache_root/apt/$(basename "$rootfs")"
  mkdir -p "$package_cache"
  resolver_target=""
  resolver_backup="$work_root/$(basename "$rootfs").resolv.conf"
  if [ -L "$rootfs/etc/resolv.conf" ]; then
    resolver_target=$(readlink "$rootfs/etc/resolv.conf")
    rm -f "$rootfs/etc/resolv.conf"
  elif [ -e "$rootfs/etc/resolv.conf" ]; then
    cp -p "$rootfs/etc/resolv.conf" "$resolver_backup"
  fi
  cp -L /etc/resolv.conf "$rootfs/etc/resolv.conf"
  restore_resolver() {
    rm -f "$rootfs/etc/resolv.conf"
    if [ -n "$resolver_target" ]; then
      ln -s "$resolver_target" "$rootfs/etc/resolv.conf"
    elif [ -f "$resolver_backup" ]; then
      mv "$resolver_backup" "$rootfs/etc/resolv.conf"
    fi
  }
  mount --bind /dev "$rootfs/dev"
  mount -t proc proc "$rootfs/proc"
  mount --rbind /sys "$rootfs/sys"
  mount --bind "$package_cache" "$rootfs/var/cache/apt/archives"
  if ! chroot "$rootfs" apt-get update || ! chroot "$rootfs" env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends "$@"; then
    umount -R "$rootfs/var/cache/apt/archives" || true
    umount -R "$rootfs/dev" || true
    umount -R "$rootfs/proc" || true
    umount -R "$rootfs/sys" || true
    restore_resolver
    return 1
  fi
  umount -R "$rootfs/var/cache/apt/archives" || true
  rm -rf "$rootfs/var/cache/apt/archives/"* "$rootfs/var/lib/apt/lists/"*
  umount -R "$rootfs/dev" || true
  umount -R "$rootfs/proc" || true
  umount -R "$rootfs/sys" || true
  restore_resolver
}

install_powerdns() {
  rootfs=$1
  key="$cache_root/downloads/powerdns-auth-49-pub.asc"
  download_cached "$key" "$powerdns_key_url" "$powerdns_key_sha256" sha256sum
  install -D -m 0644 "$key" "$rootfs/etc/apt/keyrings/auth-49-pub.asc"
  printf '%s\n' "deb [signed-by=/etc/apt/keyrings/auth-49-pub.asc] $powerdns_repo $powerdns_suite main" > "$rootfs/etc/apt/sources.list.d/pdns.list"
  printf '%s\n' 'Package: pdns-*' 'Pin: origin repo.powerdns.com' 'Pin-Priority: 600' > "$rootfs/etc/apt/preferences.d/auth-49"

  install_packages "$rootfs" \
    "pdns-server=$powerdns_package_version" \
    "pdns-backend-sqlite3=$powerdns_package_version" \
    sqlite3 chrony

  installed_version=$(chroot "$rootfs" dpkg-query -W -f='${Version}' pdns-server)
  if [ "$installed_version" != "$powerdns_package_version" ]; then
    echo "HOLD: unexpected PowerDNS package version: $installed_version" >&2
    return 2
  fi
  backend_version=$(chroot "$rootfs" dpkg-query -W -f='${Version}' pdns-backend-sqlite3)
  if [ "$backend_version" != "$powerdns_package_version" ]; then
    echo "HOLD: unexpected PowerDNS SQLite backend version: $backend_version" >&2
    return 2
  fi
  if ! chroot "$rootfs" /usr/sbin/pdns_server --version 2>&1 | grep -q '4\.9\.17'; then
    echo "HOLD: PowerDNS executable is not the qualified 4.9.17 release" >&2
    return 2
  fi

  rm -f "$rootfs/etc/apt/sources.list.d/pdns.list" \
    "$rootfs/etc/apt/preferences.d/auth-49" \
    "$rootfs/etc/apt/keyrings/auth-49-pub.asc"
}

install_pulse() {
  rootfs=$1
  release="$cache_root/downloads/pulse-v${pulse_version}-linux-amd64.tar.gz"
  download_cached "$release" "$pulse_release_url" "$pulse_release_sha256" sha256sum
  install_packages "$rootfs" nginx
  install -D -m 0755 /dev/null "$rootfs/opt/pulse/bin/pulse"
  tar -xOf "$release" ./bin/pulse > "$rootfs/opt/pulse/bin/pulse"
  chmod 0755 "$rootfs/opt/pulse/bin/pulse"
  install -D -m 0644 /dev/null "$rootfs/opt/pulse/VERSION"
  tar -xOf "$release" ./VERSION > "$rootfs/opt/pulse/VERSION"
  if ! grep -Fxq "$pulse_version" "$rootfs/opt/pulse/VERSION"; then
    echo "HOLD: Pulse archive VERSION does not match the qualified release" >&2
    return 2
  fi
  chroot "$rootfs" useradd --system --home-dir /var/lib/pulse --create-home --shell /usr/sbin/nologin pulse
  chroot "$rootfs" chown -R pulse:pulse /var/lib/pulse /opt/pulse
}

package_lxc() {
  name=$1
  rootfs=$(rootfs_for "$name")
  rm -f "$rootfs/etc/ssl/private/ssl-cert-snakeoil.key"
  rootfs_apparent_bytes=$(du -sx --apparent-size --block-size=1 "$rootfs" | awk '{print $1}')
  rootfs_allocated_bytes=$(du -sx --block-size=1 "$rootfs" | awk '{print $1}')
  rootfs_file_count=$(find "$rootfs" -xdev -type f -printf '.' | wc -c | tr -d ' ')
  printf '%s\n' "boetticher package stage: $name smoke"
  destination="$output_root/$name"
  mkdir -p "$destination"
  ./scripts/smoke-appliance.sh "$name" "$rootfs" > "$destination/smoke.txt"
  printf '%s\n' "boetticher package stage: $name manifest"
  chroot "$rootfs" dpkg-query -W -f='${binary:Package}\t${Version}\n' | sort > "$destination/package-manifest.txt"
  printf '%s\n' "boetticher package stage: $name archive"
  artifact_path=$(artifact_for "$name")
  compression_timing="$work_root/$name-compression.time"
  /usr/bin/time -f '%e %U %S' -o "$compression_timing" \
    sh -c 'tar --numeric-owner --xattrs --acls -C "$1" -cf - . | zstd -T0 "-$2" -o "$3"' \
    sh "$rootfs" "$zstd_level" "$artifact_path"
  compression_finished=$(timing_now_ms)
  artifact_size=$(stat -c '%s' "$artifact_path")
  compression_wall_ms=$(awk '{printf "%d", $1 * 1000}' "$compression_timing")
  compression_user_ms=$(awk '{printf "%d", $2 * 1000}' "$compression_timing")
  compression_system_ms=$(awk '{printf "%d", $3 * 1000}' "$compression_timing")
  compression_ratio=$(awk -v raw="$rootfs_apparent_bytes" -v compressed="$artifact_size" 'BEGIN { if (compressed > 0) printf "%.6f", raw / compressed; else print "0" }')
  build_duration_ms=
  if [ -n "${artifact_build_start_ms:-}" ]; then
    build_duration_ms=$((compression_finished - artifact_build_start_ms))
  fi
  measurement_emit "artifact_inventory" "artifact=$name" "rootfs_apparent_bytes=$rootfs_apparent_bytes" "rootfs_allocated_bytes=$rootfs_allocated_bytes" "file_count=$rootfs_file_count" "compressed_bytes=$artifact_size"
  measurement_emit "artifact_compression" "artifact=$name" "codec=zstd" "level=$zstd_level" "duration_ms=$compression_wall_ms" "cpu_user_ms=$compression_user_ms" "cpu_system_ms=$compression_system_ms" "size_bytes=$artifact_size" "compression_ratio=$compression_ratio" "build_duration_ms=${build_duration_ms:-0}"
  printf '%s\n' "boetticher package stage: $name checksum"
  sha256sum "$artifact_path" > "$destination/content.sha256"
}

build_base() {
  rootfs=$(rootfs_for boetticher-base)
  printf '%s\n' 'boetticher build stage: base rootfs'
  create_base_rootfs "$rootfs"
  printf '%s\n' 'boetticher build stage: base identity'
  write_artifact_identity "$rootfs" base
  printf '%s\n' 'boetticher build stage: base package'
  package_lxc boetticher-base
}

build_dns_blocky() {
  printf '%s\n' 'boetticher build stage: dns blocky'
  rootfs=$(prepare_rootfs boetticher-dns-blocky)
  install_powerdns "$rootfs"
  install -D -m 0644 images/dns/common/filtering-policy.hosts "$rootfs/etc/boetticher/dns/filtering/boetticher.hosts"
  mkdir -p "$rootfs/usr/local/bin"
  archive="$cache_root/downloads/blocky_v0.34.0_Linux_x86_64.tar.gz"
  download_cached "$archive" https://github.com/0xERR0R/blocky/releases/download/v0.34.0/blocky_v0.34.0_Linux_x86_64.tar.gz 17b03f892346a160e9faf974ce68baae85fa4f2a94d7bf8ea52592a94be5eeb4 sha256sum
  tar -xOf "$archive" blocky > "$rootfs/usr/local/bin/blocky"
  chmod 0755 "$rootfs/usr/local/bin/blocky"
  blocky_config="$work_root/blocky-config.yml"
  go run ./cmd/render-blocky-config > "$blocky_config"
  install -D -m 0644 "$blocky_config" "$rootfs/tmp/blocky-config.yml"
  if ! chroot "$rootfs" /usr/local/bin/blocky validate --config /tmp/blocky-config.yml; then
    echo "HOLD: pinned Blocky rejected the canonical generated configuration" >&2
    return 2
  fi
  rm -f "$rootfs/tmp/blocky-config.yml"
  chroot "$rootfs" useradd --system --home-dir /var/lib/blocky --create-home --shell /usr/sbin/nologin blocky
  cat > "$rootfs/etc/systemd/system/blocky.service" <<'EOF'
[Unit]
Description=Boetticher Blocky recursive resolver
After=network-online.target
ConditionPathExists=/etc/blocky/config.yml

[Service]
User=blocky
Group=blocky
ExecStart=/usr/local/bin/blocky --config /etc/blocky/config.yml
Restart=on-failure
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/blocky
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
  mkdir -p "$rootfs/etc/blocky"
  write_artifact_identity "$rootfs" dns
  package_lxc boetticher-dns-blocky
}

build_logging() {
  printf '%s\n' 'boetticher build stage: logging'
  rootfs=$(prepare_rootfs boetticher-logging)
  install_packages "$rootfs" systemd-journal-remote nginx
  CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$rootfs/usr/local/libexec/boetticher-log-query" ./cmd/boetticher-log-query
  install -D -m 0644 images/logging/runtime/boetticher-log-query.service "$rootfs/etc/systemd/system/boetticher-log-query.service"
  chroot "$rootfs" useradd --system --user-group --no-create-home --shell /usr/sbin/nologin boetticher-log-query
  write_artifact_identity "$rootfs" logging
  package_lxc boetticher-logging
}

build_monitoring() {
  printf '%s\n' 'boetticher build stage: monitoring'
  rootfs=$(prepare_rootfs boetticher-monitoring)
  install_pulse "$rootfs"
  install -D -m 0755 images/monitoring/runtime/run-pulse.sh "$rootfs/usr/lib/boetticher/run-pulse"
  chmod 0755 "$rootfs/usr/lib/boetticher"
  install -D -m 0644 images/monitoring/runtime/pulse.service "$rootfs/etc/systemd/system/pulse.service"
  write_artifact_identity "$rootfs" monitoring
  package_lxc boetticher-monitoring
}

build_portal() {
  printf '%s\n' 'boetticher build stage: portal'
  rootfs=$(prepare_rootfs boetticher-portal)
  install_packages "$rootfs" nginx
  write_artifact_identity "$rootfs" portal
  package_lxc boetticher-portal
}

build_tailnet_router() {
  printf '%s\n' 'boetticher build stage: tailnet-router'
  rootfs=$(prepare_rootfs boetticher-tailnet-router)
  key="$cache_root/downloads/tailscale-trixie.noarmor.gpg"
  download_cached "$key" "$tailscale_key_url" "$tailscale_key_sha256" sha256sum
  install -D -m 0644 "$key" "$rootfs$tailscale_keyring"
  printf '%s\n' "deb [signed-by=$tailscale_keyring] https://pkgs.tailscale.com/stable/debian trixie main" > "$rootfs/etc/apt/sources.list.d/tailscale.list"
  install_packages "$rootfs" dbus "tailscale=$tailscale_package_version"
  installed_version=$(chroot "$rootfs" dpkg-query -W -f='${Version}' tailscale)
  if [ "$installed_version" != "$tailscale_package_version" ]; then
    echo "HOLD: unexpected Tailscale package version: $installed_version" >&2
    return 2
  fi
  rm -f "$rootfs/etc/apt/sources.list.d/tailscale.list" "$rootfs$tailscale_keyring"
  write_artifact_identity "$rootfs" tailnet-router
  package_lxc boetticher-tailnet-router
}

build_airvpn() {
  printf '%s\n' 'boetticher build stage: airvpn'
  rootfs=$(prepare_rootfs boetticher-airvpn)
  install_packages "$rootfs" wireguard-tools wireguard-go nftables iproute2
  install -D -m 0644 images/airvpn/runtime/boetticher-airvpn.service "$rootfs/etc/systemd/system/boetticher-airvpn.service"
  install -D -m 0755 images/airvpn/runtime/airvpn-prepare "$rootfs/usr/lib/boetticher/airvpn-prepare"
  install -D -m 0755 images/airvpn/runtime/airvpn-routes-up "$rootfs/usr/lib/boetticher/airvpn-routes-up"
  install -D -m 0755 images/airvpn/runtime/airvpn-routes-down "$rootfs/usr/lib/boetticher/airvpn-routes-down"
  install -D -m 0755 images/airvpn/runtime/airvpn-forwarding-up "$rootfs/usr/lib/boetticher/airvpn-forwarding-up"
  install -D -m 0755 images/airvpn/runtime/airvpn-forwarding-down "$rootfs/usr/lib/boetticher/airvpn-forwarding-down"
  write_artifact_identity "$rootfs" airvpn
  package_lxc boetticher-airvpn
}

build_bifrost() {
  printf '%s\n' 'boetticher build stage: bifrost'
  rootfs=$(prepare_rootfs boetticher-bifrost)
  install_packages "$rootfs" "nginx=$bifrost_nginx_package_version"
  chroot "$rootfs" useradd --system --home-dir /var/lib/bifrost --create-home --shell /usr/sbin/nologin bifrost
  chroot "$rootfs" install -d -o bifrost -g bifrost -m 0750 /var/lib/bifrost
  rm -f "$rootfs/etc/nginx/sites-enabled/default" "$rootfs/etc/nginx/sites-available/default" "$rootfs/etc/ssl/private/ssl-cert-snakeoil.key"
  install -D -m 0644 images/bifrost/runtime/bifrost.service "$rootfs/etc/systemd/system/bifrost.service"
  CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$rootfs/usr/local/libexec/boetticher-bifrost" ./cmd/boetticher-bifrost
  ln -s boetticher-bifrost "$rootfs/usr/local/libexec/boetticher-bifrost-model-capabilities"
  write_artifact_identity "$rootfs" bifrost
  package_lxc boetticher-bifrost
}

build_printer() {
  printf '%s\n' 'boetticher build stage: printer'
  rootfs=$(prepare_rootfs boetticher-printer)
  install_packages "$rootfs" python3=3.13.5-1 python3-venv=3.13.5-1 python3-pip=25.1.1+dfsg-1 python3-dev build-essential nginx=1.26.3-3+deb13u7
  chroot "$rootfs" groupadd --system --gid 2200 octoprint
  chroot "$rootfs" useradd --system --uid 2200 --gid 2200 --home-dir /var/lib/octoprint --create-home --shell /usr/sbin/nologin octoprint
  chroot "$rootfs" python3 -m venv /opt/octoprint
  install -D -m 0644 images/printer/runtime/requirements.lock "$rootfs/tmp/octoprint-requirements.lock"
  pip_install "$rootfs" /opt/octoprint/bin/pip install --require-hashes --requirement /tmp/octoprint-requirements.lock
  chroot "$rootfs" apt-get purge --yes --auto-remove python3-dev build-essential
  chroot "$rootfs" apt-get clean
  rm -rf "$rootfs/var/lib/apt/lists/"*
  install -D -m 0644 images/printer/runtime/octoprint.service "$rootfs/etc/systemd/system/octoprint.service"
  rm -f "$rootfs/tmp/octoprint-requirements.lock" "$rootfs/etc/nginx/sites-enabled/default"
  write_artifact_identity "$rootfs" printer
  package_lxc boetticher-printer
}

build_arr() {
  printf '%s\n' 'boetticher build stage: arr'
  rootfs=$(prepare_rootfs boetticher-arr)
  install_packages "$rootfs" "nginx=$arr_nginx_package_version" ca-certificates
  sonarr_archive="$cache_root/downloads/Sonarr.main.$sonarr_version.linux-x64.tar.gz"
  radarr_archive="$cache_root/downloads/Radarr.master.$radarr_version.linux-core-x64.tar.gz"
  download_cached "$sonarr_archive" "$sonarr_release_url" "$sonarr_release_sha256" sha256sum
  download_cached "$radarr_archive" "$radarr_release_url" "$radarr_release_sha256" sha256sum
  sonarr_root="$work_root/sonarr-$sonarr_version"; radarr_root="$work_root/radarr-$radarr_version"
  rm -rf "$sonarr_root" "$radarr_root"
  mkdir -p "$sonarr_root" "$radarr_root"
  tar -xzf "$sonarr_archive" -C "$sonarr_root" --strip-components=1
  tar -xzf "$radarr_archive" -C "$radarr_root" --strip-components=1
  install -d -m 0755 "$rootfs/opt/sonarr" "$rootfs/opt/radarr"
  cp -a "$sonarr_root/." "$rootfs/opt/sonarr/"
  cp -a "$radarr_root/." "$rootfs/opt/radarr/"
  chroot "$rootfs" groupadd --system --gid 2200 arr
  chroot "$rootfs" useradd --system --uid 2200 --gid 2200 --home-dir /var/lib/arr/sonarr --create-home --shell /usr/sbin/nologin sonarr
  chroot "$rootfs" useradd --system --uid 2201 --gid 2200 --home-dir /var/lib/arr/radarr --create-home --shell /usr/sbin/nologin radarr
  chroot "$rootfs" install -d -o sonarr -g arr -m 0750 /var/lib/arr/sonarr
  chroot "$rootfs" install -d -o radarr -g arr -m 0750 /var/lib/arr/radarr
  chroot "$rootfs" chown -R root:root /opt/sonarr /opt/radarr
  chroot "$rootfs" chmod -R u+rwX,go+rX,go-w /opt/sonarr /opt/radarr
  install -D -m 0644 images/arr/runtime/sonarr.service "$rootfs/etc/systemd/system/sonarr.service"
  install -D -m 0644 images/arr/runtime/radarr.service "$rootfs/etc/systemd/system/radarr.service"
  rm -f "$rootfs/etc/nginx/sites-enabled/default" "$rootfs/etc/ssl/private/ssl-cert-snakeoil.key"
  chroot "$rootfs" apt-get clean
  rm -rf "$rootfs/var/lib/apt/lists/"*
  write_artifact_identity "$rootfs" arr
  package_lxc boetticher-arr
}

build_aiops() {
  printf '%s\n' 'boetticher build stage: aiops'
  rootfs=$(prepare_rootfs boetticher-aiops)
  install_packages "$rootfs" \
    "python3=$aiops_python_package_version" \
    "python3-venv=$aiops_python_venv_package_version" \
    "python3-pip=$aiops_pip_package_version"
  chroot "$rootfs" python3 -m venv /opt/holmes
  install -D -m 0644 images/aiops/runtime/requirements.lock "$rootfs/tmp/aiops-requirements.lock"
  pip_install "$rootfs" /opt/holmes/bin/pip install --require-hashes --requirement /tmp/aiops-requirements.lock
  chroot "$rootfs" /opt/holmes/bin/python -c 'import importlib.metadata; assert importlib.metadata.version("holmesgpt") == "0.40.0"'
  holmes_archive="$cache_root/downloads/holmesgpt-0.40.0.tar.gz"
  download_cached "$holmes_archive" "$holmes_source_url" "$holmes_source_sha256" sha256sum
  tar -xOf "$holmes_archive" "$holmes_source_root/server.py" > "$rootfs/opt/holmes/server.py"
  chmod 0644 "$rootfs/opt/holmes/server.py"
  rm -f "$rootfs/tmp/aiops-requirements.lock"
  CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$rootfs/usr/local/libexec/boetticher-aiops" ./cmd/boetticher-aiops
  chroot "$rootfs" useradd --system --home-dir /var/lib/boetticher/aiops --shell /usr/sbin/nologin boetticher-aiops
  chroot "$rootfs" useradd --system --no-create-home --shell /usr/sbin/nologin holmes
  install -D -m 0644 images/aiops/runtime/boetticher-aiops.service "$rootfs/etc/systemd/system/boetticher-aiops.service"
  install -D -m 0644 images/aiops/runtime/boetticher-aiops.socket "$rootfs/etc/systemd/system/boetticher-aiops.socket"
  install -D -m 0644 images/aiops/runtime/holmes.service "$rootfs/etc/systemd/system/holmes.service"
  install -D -m 0644 images/aiops/runtime/holmes.yaml "$rootfs/etc/boetticher-aiops/config.yaml"
  write_artifact_identity "$rootfs" aiops
  package_lxc boetticher-aiops
}

build_firewall() {
  printf '%s\n' 'boetticher build stage: firewall'
  for tool in qemu-img virt-customize virt-cat sha512sum; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      echo "HOLD: required firewall VM-image tool is unavailable: $tool" >&2
      return 2
    fi
  done
  destination="$output_root/boetticher-firewall"
  mkdir -p "$destination"
  input="$cache_root/downloads/debian-13-genericcloud-amd64-20260327-2429.qcow2"
  download_cached "$input" https://cloud.debian.org/images/cloud/trixie/20260327-2429/debian-13-genericcloud-amd64-20260327-2429.qcow2 09559ec27d263997827dd8cddf76e97ea8e0f1803380aa501ea7eaa4b4968cd76ffef4ec7eb07ef1a9ccbeb0925a5020492ea9ed53eb167d62f3a2285039912c sha512sum
  image="$destination/boetticher-firewall-1.0.0-amd64.qcow2"
  artifact_identity="$work_root/firewall-artifact.json"
  telemetry_binary="$work_root/boetticher-firewall-telemetry"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$telemetry_binary" ./cmd/boetticher-firewall-telemetry
  go run ./cmd/artifact-identity -module firewall > "$artifact_identity"
  cp "$input" "$image"
  virt-customize -a "$image" \
    --network \
    --upload images/base/runtime/debian-snapshot.sources:/etc/apt/sources.list.d/boetticher-debian.sources \
    --upload images/base/runtime/debian-security-snapshot.sources:/etc/apt/sources.list.d/boetticher-debian-security.sources \
    --run-command 'rm -f /etc/apt/sources.list.d/debian.sources /etc/apt/sources.list; apt-get -o Acquire::Check-Valid-Until=false update' \
    --run-command 'DEBIAN_FRONTEND=noninteractive apt-get upgrade --yes --no-install-recommends' \
    --run-command 'DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends nftables kea-dhcp4-server kea-dhcp-ddns-server dnsmasq chrony openssh-server sudo cloud-init systemd-journal-remote curl jq openssl qemu-guest-agent' \
    --run-command 'apt-get clean; rm -rf /var/lib/apt/lists/*' \
    --mkdir /etc/boetticher \
    --mkdir /usr/lib/boetticher \
    --mkdir /var/lib/boetticher/identity/ssh \
    --mkdir /var/lib/boetticher/firewall-telemetry \
    --mkdir /tmp/boetticher-ansible \
    --mkdir /etc/ssh/sshd_config.d \
    --mkdir /etc/systemd/journald.conf.d \
    --mkdir /etc/sysctl.d \
    --upload images/base/first-boot/boetticher-first-boot.sh:/usr/lib/boetticher/boetticher-first-boot.sh \
    --upload images/base/first-boot/boetticher-first-boot.service:/etc/systemd/system/boetticher-first-boot.service \
    --upload images/base/runtime/install-runtime-state.sh:/usr/lib/boetticher/install-runtime-state \
    --upload images/firewall/nocloud/network-config:/etc/boetticher/nocloud-network-config \
    --upload images/base/runtime/journald.conf:/etc/systemd/journald.conf.d/boetticher.conf \
    --upload images/base/runtime/journal-upload.conf:/etc/systemd/journal-upload.conf \
    --upload images/base/runtime/sshd.conf:/etc/ssh/sshd_config.d/boetticher.conf \
    --upload images/base/runtime/sshd-host-key.conf:/etc/ssh/sshd_config.d/boetticher-host-key.conf \
    --upload images/firewall/runtime/boetticher.sudoers:/etc/sudoers.d/boetticher-firewall \
    --upload images/firewall/runtime/inspect-firewall.sh:/usr/lib/boetticher/inspect-firewall \
    --upload "$telemetry_binary:/usr/lib/boetticher/boetticher-firewall-telemetry" \
    --upload images/firewall/runtime/snapshot-firewall.sh:/usr/lib/boetticher/snapshot-firewall \
    --upload images/firewall/runtime/boetticher-firewall-snapshot.service:/etc/systemd/system/boetticher-firewall-snapshot.service \
    --upload images/firewall/runtime/boetticher-firewall-snapshot.timer:/etc/systemd/system/boetticher-firewall-snapshot.timer \
    --upload images/firewall/runtime/boetticher-firewall-telemetry.service:/etc/systemd/system/boetticher-firewall-telemetry.service \
    --upload "$artifact_identity:/usr/lib/boetticher/artifact.json" \
    --upload images/firewall/runtime/forwarding.conf:/etc/sysctl.d/boetticher-forwarding.conf \
    --run-command 'useradd --create-home --shell /bin/bash labadmin' \
    --run-command 'passwd --lock labadmin' \
    --run-command 'chown labadmin:labadmin /tmp/boetticher-ansible && chmod 0700 /tmp/boetticher-ansible' \
    --run-command 'chown root:root /etc/sudoers.d/boetticher-firewall; chmod 0440 /etc/sudoers.d/boetticher-firewall' \
    --run-command 'chown root:root /usr/lib/boetticher/inspect-firewall; chmod 0755 /usr/lib/boetticher/inspect-firewall' \
    --run-command 'groupadd --system boetticher-telemetry; useradd --system --gid boetticher-telemetry --home-dir /var/lib/boetticher/firewall-telemetry --shell /usr/sbin/nologin boetticher-telemetry' \
    --run-command 'chown boetticher-telemetry:boetticher-telemetry /var/lib/boetticher/firewall-telemetry; chmod 0750 /var/lib/boetticher/firewall-telemetry' \
    --run-command 'chown root:root /usr/lib/boetticher/boetticher-firewall-telemetry /usr/lib/boetticher/snapshot-firewall; chmod 0755 /usr/lib/boetticher/boetticher-firewall-telemetry /usr/lib/boetticher/snapshot-firewall' \
    --run-command 'chmod 0644 /etc/systemd/system/boetticher-firewall-snapshot.service /etc/systemd/system/boetticher-firewall-snapshot.timer /etc/systemd/system/boetticher-firewall-telemetry.service' \
    --run-command 'rm -f /etc/ssh/ssh_host_* /root/.ssh/authorized_keys /home/labadmin/.ssh/authorized_keys' \
    --run-command 'rm -f /etc/ssl/private/ssl-cert-snakeoil.key' \
    --run-command 'visudo -cf /etc/sudoers' \
    --run-command "dpkg-query -W -f='\${binary:Package}\\t\${Version}\\n' | sort > /var/lib/boetticher/package-manifest.txt" \
    --run-command 'systemctl enable boetticher-first-boot.service' \
    --run-command 'systemctl enable boetticher-firewall-telemetry.service boetticher-firewall-snapshot.timer' \
    --run-command 'if systemctl list-unit-files systemd-networkd-wait-online.service >/dev/null 2>&1; then systemctl disable systemd-networkd-wait-online.service; fi'
  sha256sum "$image" > "$destination/content.sha256"
  virt-cat -a "$image" /var/lib/boetticher/package-manifest.txt > "$destination/package-manifest.txt"
  ./scripts/smoke-firewall-image.sh "$image" > "$destination/smoke.txt"
}

image_artifact_name() {
  printf 'boetticher-%s\n' "${1#image-}"
}

launch_image_worker() {
  worker_target=$1
  worker_name=${worker_target#image-}
  worker_artifact=$(image_artifact_name "$worker_target")
  worker_root="$work_root/workers/$worker_name"
  worker_log="$output_root/$worker_artifact/build.log"
  mkdir -p "$worker_root" "$(dirname "$worker_log")"
  BOETTICHER_IMAGE_WORK="$worker_root" \
  BOETTICHER_BASE_ROOTFS="$base_rootfs" \
  BOETTICHER_SKIP_PROVENANCE=1 \
  BOETTICHER_TIMING_LOG="$worker_root/timings.log" \
    "$script_path" "$worker_target" >"$worker_log" 2>&1 &
  worker_pid=$!
}

append_worker_timings() {
  worker_root=$1
  if [ -f "$worker_root/timings.log" ]; then
    cat "$worker_root/timings.log"
    if [ -n "$timing_log" ]; then
      cat "$worker_root/timings.log" >> "$timing_log"
    fi
  fi
}

wait_image_worker() {
  worker_pid=$1
  worker_target=$2
  worker_root=$3
  worker_log=$4
  if wait "$worker_pid"; then
    worker_status=0
  else
    worker_status=$?
  fi
  append_worker_timings "$worker_root"
  if [ "$worker_status" -ne 0 ]; then
    cat "$worker_log" >&2
  fi
  return "$worker_status"
}

contains_image_target() {
  case " $selected_image_targets " in
    *" $1 "*) return 0 ;;
    *) return 1 ;;
  esac
}

build_selected_images() {
  build_started=$(timing_now_ms)
  timing_log="$output_root/build-timings.log"
  : > "$timing_log"
  mkdir -p "$work_root/workers"
  base_rootfs=$(rootfs_for boetticher-base)

  normalized_image_targets=
  for selected_target in $selected_image_targets; do
    case " $normalized_image_targets " in
      *" $selected_target "*) ;;
      *) normalized_image_targets="$normalized_image_targets $selected_target" ;;
    esac
  done
  selected_image_targets=$(printf '%s\n' "$normalized_image_targets" | sed 's/^ *//')
  need_base=0
  for selected_target in $selected_image_targets; do
    if [ "$selected_target" != image-base ] && [ "$selected_target" != image-firewall ]; then
      need_base=1
    fi
  done
  if [ "$need_base" -eq 1 ] && ! contains_image_target image-base; then
    selected_image_targets="image-base $selected_image_targets"
  fi

  failed=0
  pid_a=
  pid_b=
  # Base and firewall are both memory-heavy: keep them sequential on the
  # bounded builder. Derived appliance workers retain bounded concurrency.
  if contains_image_target image-base; then
    launch_image_worker image-base
    pid_a=$worker_pid
    root_a=$worker_root
    log_a=$worker_log
    if ! wait_image_worker "$pid_a" "${root_a##*/}" "$root_a" "$log_a"; then
      failed=1
    fi
    pid_a=
  fi
  if [ "$failed" -eq 0 ] && contains_image_target image-firewall; then
    launch_image_worker image-firewall
    if ! wait_image_worker "$worker_pid" "${worker_root##*/}" "$worker_root" "$worker_log"; then
      failed=1
    fi
  fi
  if [ -n "$pid_b" ]; then
    if ! wait_image_worker "$pid_b" "${root_b##*/}" "$root_b" "$log_b"; then
      failed=1
    fi
    pid_b=
  fi
  if [ "$failed" -ne 0 ]; then
    build_finished=$(timing_now_ms)
    timing_emit "artifact_build_all" "$((build_finished - build_started))"
    return 1
  fi

  for selected_target in $selected_image_targets; do
    case "$selected_target" in
      image-base|image-firewall) continue ;;
    esac
    if [ -n "$pid_a" ] && [ -n "$pid_b" ]; then
      if ! wait_image_worker "$pid_a" "${root_a##*/}" "$root_a" "$log_a"; then
        failed=1
      fi
      pid_a=
      if [ -n "$pid_b" ]; then
        if ! wait_image_worker "$pid_b" "${root_b##*/}" "$root_b" "$log_b"; then
          failed=1
        fi
        pid_b=
      fi
      if [ "$failed" -ne 0 ]; then
        break
      fi
    fi
    launch_image_worker "$selected_target"
    if [ -z "$pid_a" ]; then
      pid_a=$worker_pid
      root_a=$worker_root
      log_a=$worker_log
    else
      pid_b=$worker_pid
      root_b=$worker_root
      log_b=$worker_log
    fi
  done
  if [ -n "$pid_a" ]; then
    if ! wait_image_worker "$pid_a" "${root_a##*/}" "$root_a" "$log_a"; then
      failed=1
    fi
  fi
  if [ -n "$pid_b" ]; then
    if ! wait_image_worker "$pid_b" "${root_b##*/}" "$root_b" "$log_b"; then
      failed=1
    fi
  fi
  build_finished=$(timing_now_ms)
  timing_emit "artifact_build_all" "$((build_finished - build_started))"
  if [ "$failed" -ne 0 ]; then
    return 1
  fi
}

run_timed_image_target() {
  timed_target=$1
  shift
  timed_start=$(timing_now_ms)
  artifact_build_start_ms=$timed_start
  "$@"
  timed_finish=$(timing_now_ms)
  timing_emit "artifact_build" "$((timed_finish - timed_start))" "$(image_artifact_name "$timed_target")"
}

build_dns_blocky_target() {
  [ -f "$(artifact_for boetticher-base)" ] || build_base
  build_dns_blocky
}

build_logging_target() {
  [ -f "$(artifact_for boetticher-base)" ] || build_base
  build_logging
}

build_monitoring_target() {
  [ -f "$(artifact_for boetticher-base)" ] || build_base
  build_monitoring
}

build_portal_target() {
  [ -f "$(artifact_for boetticher-base)" ] || build_base
  build_portal
}

build_tailnet_router_target() {
  [ -f "$(artifact_for boetticher-base)" ] || build_base
  build_tailnet_router
}

build_airvpn_target() {
  [ -f "$(artifact_for boetticher-base)" ] || build_base
  build_airvpn
}

build_bifrost_target() {
  [ -f "$(artifact_for boetticher-base)" ] || build_base
  build_bifrost
}

build_printer_target() {
  [ -f "$(artifact_for boetticher-base)" ] || build_base
  build_printer
}

build_arr_target() {
  [ -f "$(artifact_for boetticher-base)" ] || build_base
  build_arr
}

build_aiops_target() {
  [ -f "$(artifact_for boetticher-base)" ] || build_base
  build_aiops
}

build_gatus_target() {
  [ -f "$(artifact_for boetticher-base)" ] || build_base
  rootfs=$(prepare_rootfs boetticher-gatus)
  install_packages "$rootfs" nginx ca-certificates
  archive="$cache_root/downloads/gatus-v5.36.0.tar.gz"
  download_cached "$archive" "$gatus_source_url" "$gatus_source_sha256" sha256sum
  source_root="$work_root/gatus-source"; rm -rf "$source_root"; mkdir -p "$source_root"
  tar -xzf "$archive" -C "$source_root" --strip-components=1
  (cd "$source_root" && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$rootfs/usr/local/bin/gatus" .)
  chmod 0755 "$rootfs/usr/local/bin/gatus"
  chroot "$rootfs" useradd --system --home-dir /var/lib/gatus --create-home --shell /usr/sbin/nologin gatus
  install -D -m 0644 images/gatus/runtime/gatus.service "$rootfs/etc/systemd/system/gatus.service"
  write_artifact_identity "$rootfs" gatus
  package_lxc boetticher-gatus
}

build_network_probe_target() {
  printf '%s\n' 'boetticher build stage: network probe'
  rootfs=$(prepare_rootfs boetticher-network-probe)
  install_packages "$rootfs" arping dnsutils isc-dhcp-client iperf3 netcat-openbsd nmap tcpdump
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o "$rootfs/usr/local/libexec/boetticher-network-probe" ./cmd/boetticher-network-probe
  chmod 0755 "$rootfs/usr/local/libexec/boetticher-network-probe"
  write_artifact_identity "$rootfs" network-probe
  package_lxc boetticher-network-probe
}

case "$target" in
  image-base) run_timed_image_target "$target" build_base ;;
  image-dns-blocky) run_timed_image_target "$target" build_dns_blocky_target ;;
  image-logging) run_timed_image_target "$target" build_logging_target ;;
  image-monitoring) run_timed_image_target "$target" build_monitoring_target ;;
  image-portal) run_timed_image_target "$target" build_portal_target ;;
  image-tailnet-router) run_timed_image_target "$target" build_tailnet_router_target ;;
  image-airvpn) run_timed_image_target "$target" build_airvpn_target ;;
  image-bifrost) run_timed_image_target "$target" build_bifrost_target ;;
  image-printer) run_timed_image_target "$target" build_printer_target ;;
  image-arr) run_timed_image_target "$target" build_arr_target ;;
  image-aiops) run_timed_image_target "$target" build_aiops_target ;;
  image-gatus) run_timed_image_target "$target" build_gatus_target ;;
  image-network-probe) run_timed_image_target "$target" build_network_probe_target ;;
  image-firewall) run_timed_image_target "$target" build_firewall ;;
  images) build_selected_images ;;
esac
