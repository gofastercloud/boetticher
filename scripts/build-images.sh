#!/bin/sh
set -eu

# Linux-native appliance construction. The builder VM and a Linux controller
# execute this same script; macOS controllers intentionally stop before any
# image tooling is attempted.
target=${1:-images}
shift || true
case "$target" in
  image-base|image-dns-blocky|image-dns-adguard|image-logging|image-monitoring|image-portal|image-firewall|image-tailnet-router|image-litellm|image-streamdeck|images) ;;
  *) echo "unknown image target: $target" >&2; exit 2 ;;
esac

default_image_targets="image-base image-dns-blocky image-logging image-monitoring image-portal image-tailnet-router image-litellm image-streamdeck image-firewall"
if [ "$target" = images ]; then
  selected_image_targets="$*"
  if [ -z "$selected_image_targets" ]; then
    selected_image_targets=$default_image_targets
  fi
  for selected_target in $selected_image_targets; do
    case "$selected_target" in
      image-base|image-dns-blocky|image-dns-adguard|image-logging|image-monitoring|image-portal|image-firewall|image-tailnet-router|image-litellm|image-streamdeck) ;;
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

zstd_level=${BOETTICHER_ZSTD_LEVEL:-19}
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

for tool in mmdebstrap tar zstd sha256sum curl chroot go jq stat; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "HOLD: required Linux image-build tool is unavailable: $tool" >&2
    exit 2
  fi
done

output_root=${BOETTICHER_ARTIFACT_OUTPUT:-generated/artifacts}
work_root=${BOETTICHER_IMAGE_WORK:-/tmp/boetticher-image-build}
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
litellm_version=1.74.9
litellm_python_package_version=3.13.5-1
litellm_python_venv_package_version=3.13.5-1
litellm_pip_package_version=25.1.1+dfsg-1
litellm_nginx_package_version=1.26.3-3+deb13u7
mkdir -p "$output_root" "$work_root"

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
    --arg boetticher_version 0.3.34 \
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
		version=0.3.34
	fi
	printf '%s/%s/%s-%s-amd64.tar.zst' "$output_root" "$name" "$name" "$version"
}

create_base_rootfs() {
  rootfs=$1
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
}

write_artifact_identity() {
  rootfs=$1
  module=$2
  provider=${3:-}
  if [ -n "$provider" ]; then
    go run ./cmd/artifact-identity -module "$module" -provider "$provider" > "$rootfs/usr/lib/boetticher/artifact.json"
  else
    go run ./cmd/artifact-identity -module "$module" > "$rootfs/usr/lib/boetticher/artifact.json"
  fi
  chmod 0644 "$rootfs/usr/lib/boetticher/artifact.json"
}

prepare_rootfs() {
  name=$1
  rootfs=$(rootfs_for "$name")
  if [ ! -d "$(rootfs_for boetticher-base)/etc" ]; then
    create_base_rootfs "$(rootfs_for boetticher-base)"
  fi
  rm -rf "$rootfs"
  cp -a "$(rootfs_for boetticher-base)" "$rootfs"
  ACTIVE_ROOT=$rootfs
  mkdir -p "$rootfs/var/lib/boetticher/identity/ssh" "$rootfs/etc/boetticher" "$rootfs/usr/lib/boetticher"
  printf '%s\n' "artifact=$name" > "$rootfs/usr/lib/boetticher/build-input.txt"
  printf '%s\n' "$rootfs"
}

install_packages() {
  rootfs=$1
  shift
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
  if ! chroot "$rootfs" apt-get update || ! chroot "$rootfs" env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends "$@"; then
    umount -R "$rootfs/dev" || true
    umount -R "$rootfs/proc" || true
    umount -R "$rootfs/sys" || true
    restore_resolver
    return 1
  fi
  chroot "$rootfs" apt-get clean
  rm -rf "$rootfs/var/lib/apt/lists/"*
  umount -R "$rootfs/dev" || true
  umount -R "$rootfs/proc" || true
  umount -R "$rootfs/sys" || true
  restore_resolver
}

install_powerdns() {
  rootfs=$1
  key="$work_root/powerdns-auth-49-pub.asc"
  if [ ! -f "$key" ]; then
    curl --fail --location --silent --show-error --output "$key" "$powerdns_key_url"
  fi
  printf '%s  %s\n' "$powerdns_key_sha256" "$key" | sha256sum --check --status
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
  release="$work_root/pulse-v${pulse_version}-linux-amd64.tar.gz"
  if [ ! -f "$release" ]; then
    curl --fail --location --silent --show-error --output "$release" "$pulse_release_url"
  fi
  printf '%s  %s\n' "$pulse_release_sha256" "$release" | sha256sum --check --status
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
  printf '%s\n' "boetticher package stage: $name smoke"
  destination="$output_root/$name"
  mkdir -p "$destination"
  ./scripts/smoke-appliance.sh "$name" "$rootfs"
  printf '%s\n' "boetticher package stage: $name manifest"
  chroot "$rootfs" dpkg-query -W -f='${binary:Package}\t${Version}\n' | sort > "$destination/package-manifest.txt"
  printf '%s\n' "boetticher package stage: $name archive"
  compression_started=$(timing_now_ms)
  artifact_path=$(artifact_for "$name")
  tar --numeric-owner --xattrs --acls -C "$rootfs" -cf - . | zstd -T0 "-$zstd_level" -o "$artifact_path"
  compression_finished=$(timing_now_ms)
  artifact_size=$(stat -c '%s' "$artifact_path")
  measurement_emit "artifact_compression" "artifact=$name" "codec=zstd" "level=$zstd_level" "duration_ms=$((compression_finished - compression_started))" "size_bytes=$artifact_size"
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
  archive="$work_root/blocky_v0.34.0_Linux_x86_64.tar.gz"
  curl --fail --location --silent --show-error --output "$archive" https://github.com/0xERR0R/blocky/releases/download/v0.34.0/blocky_v0.34.0_Linux_x86_64.tar.gz
  printf '%s  %s\n' 17b03f892346a160e9faf974ce68baae85fa4f2a94d7bf8ea52592a94be5eeb4 "$archive" | sha256sum --check --status
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
  write_artifact_identity "$rootfs" dns blocky
  package_lxc boetticher-dns-blocky
}

build_logging() {
  printf '%s\n' 'boetticher build stage: logging'
  rootfs=$(prepare_rootfs boetticher-logging)
  install_packages "$rootfs" systemd-journal-remote
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
  key="$work_root/tailscale-trixie.noarmor.gpg"
  if [ ! -f "$key" ]; then
    curl --fail --location --silent --show-error --output "$key" "$tailscale_key_url"
  fi
  printf '%s  %s\n' "$tailscale_key_sha256" "$key" | sha256sum --check --status
  install -D -m 0644 "$key" "$rootfs$tailscale_keyring"
  printf '%s\n' "deb [signed-by=$tailscale_keyring] https://pkgs.tailscale.com/stable/debian trixie main" > "$rootfs/etc/apt/sources.list.d/tailscale.list"
  install_packages "$rootfs" "tailscale=$tailscale_package_version"
  installed_version=$(chroot "$rootfs" dpkg-query -W -f='${Version}' tailscale)
  if [ "$installed_version" != "$tailscale_package_version" ]; then
    echo "HOLD: unexpected Tailscale package version: $installed_version" >&2
    return 2
  fi
  rm -f "$rootfs/etc/apt/sources.list.d/tailscale.list" "$rootfs$tailscale_keyring"
  write_artifact_identity "$rootfs" tailnet-router
  package_lxc boetticher-tailnet-router
}

build_litellm() {
  printf '%s\n' 'boetticher build stage: litellm'
  rootfs=$(prepare_rootfs boetticher-litellm)
  install_packages "$rootfs" \
    "nginx=$litellm_nginx_package_version" \
    "python3=$litellm_python_package_version" \
    "python3-venv=$litellm_python_venv_package_version" \
    "python3-pip=$litellm_pip_package_version"
  for package in nginx python3 python3-venv python3-pip; do
    expected_version=$litellm_nginx_package_version
    if [ "$package" = python3 ] || [ "$package" = python3-venv ]; then
      expected_version=$litellm_python_package_version
    elif [ "$package" = python3-pip ]; then
      expected_version=$litellm_pip_package_version
    fi
    installed_version=$(chroot "$rootfs" dpkg-query -W -f='${Version}' "$package")
    if [ "$installed_version" != "$expected_version" ]; then
      echo "HOLD: unexpected $package version: $installed_version" >&2
      return 2
    fi
  done
  chroot "$rootfs" python3 -m venv /opt/litellm
  chroot "$rootfs" useradd --system --home-dir /var/lib/litellm --create-home --shell /usr/sbin/nologin litellm
  chroot "$rootfs" chown -R litellm:litellm /var/lib/litellm
  rm -f "$rootfs/etc/nginx/sites-enabled/default" "$rootfs/etc/nginx/sites-available/default" "$rootfs/etc/ssl/private/ssl-cert-snakeoil.key"
  install -D -m 0644 images/litellm/runtime/requirements.lock "$rootfs/tmp/litellm-requirements.lock"
  install -D -m 0644 images/litellm/runtime/litellm.service "$rootfs/etc/systemd/system/litellm.service"
  chroot "$rootfs" /opt/litellm/bin/pip install --no-cache-dir --require-hashes --requirement /tmp/litellm-requirements.lock
  installed_version=$(chroot "$rootfs" /opt/litellm/bin/python -c 'from importlib.metadata import version; print(version("litellm"))')
  if [ "$installed_version" != "$litellm_version" ]; then
    echo "HOLD: unexpected LiteLLM version: $installed_version" >&2
    return 2
  fi
  rm -f "$rootfs/tmp/litellm-requirements.lock"
  write_artifact_identity "$rootfs" litellm
  package_lxc boetticher-litellm
}

build_streamdeck() {
  printf '%s\n' 'boetticher build stage: streamdeck'
  rootfs=$(prepare_rootfs boetticher-streamdeck)
  install_packages "$rootfs" python3=3.13.5-1 python3-venv=3.13.5-1 python3-pip=25.1.1+dfsg-1 libhidapi-libusb0 fonts-dejavu-core
  chroot "$rootfs" groupadd --system --gid 2200 streamdeck
  chroot "$rootfs" useradd --system --uid 2200 --gid 2200 --home-dir /var/lib/streamdeck --create-home --shell /usr/sbin/nologin streamdeck
  chroot "$rootfs" python3 -m venv /opt/streamdeck
  install -D -m 0644 images/streamdeck/runtime/requirements.lock "$rootfs/tmp/streamdeck-requirements.lock"
  mkdir -p "$rootfs/usr/src/boetticher-streamdeck"
  cp -a services/streamdeck/pyproject.toml services/streamdeck/src "$rootfs/usr/src/boetticher-streamdeck/"
  chroot "$rootfs" /opt/streamdeck/bin/pip install --no-cache-dir --require-hashes --requirement /tmp/streamdeck-requirements.lock
  chroot "$rootfs" /opt/streamdeck/bin/pip install --no-cache-dir --no-deps --no-build-isolation /usr/src/boetticher-streamdeck
  install -D -m 0644 images/streamdeck/runtime/streamdeck-status.service "$rootfs/etc/systemd/system/streamdeck-status.service"
  rm -rf "$rootfs/usr/src/boetticher-streamdeck" "$rootfs/tmp/streamdeck-requirements.lock"
  write_artifact_identity "$rootfs" streamdeck
  package_lxc boetticher-streamdeck
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
  input="$work_root/debian-13-genericcloud-amd64-20260327-2429.qcow2"
  if [ ! -f "$input" ]; then
    curl --fail --location --silent --show-error --output "$input" https://cloud.debian.org/images/cloud/trixie/20260327-2429/debian-13-genericcloud-amd64-20260327-2429.qcow2
  fi
  printf '%s  %s\n' 09559ec27d263997827dd8cddf76e97ea8e0f1803380aa501ea7eaa4b4968cd76ffef4ec7eb07ef1a9ccbeb0925a5020492ea9ed53eb167d62f3a2285039912c "$input" | sha512sum --check --status
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
  ./scripts/smoke-firewall-image.sh "$image"
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

build_litellm_target() {
  [ -f "$(artifact_for boetticher-base)" ] || build_base
  build_litellm
}

build_streamdeck_target() {
  [ -f "$(artifact_for boetticher-base)" ] || build_base
  build_streamdeck
}

case "$target" in
  image-base) run_timed_image_target "$target" build_base ;;
  image-dns-blocky) run_timed_image_target "$target" build_dns_blocky_target ;;
  image-logging) run_timed_image_target "$target" build_logging_target ;;
  image-monitoring) run_timed_image_target "$target" build_monitoring_target ;;
  image-portal) run_timed_image_target "$target" build_portal_target ;;
  image-tailnet-router) run_timed_image_target "$target" build_tailnet_router_target ;;
  image-litellm) run_timed_image_target "$target" build_litellm_target ;;
  image-streamdeck) run_timed_image_target "$target" build_streamdeck_target ;;
  image-dns-adguard) echo "HOLD: AdGuard provider qualification is outside the default Blocky readiness tranche" >&2; exit 2 ;;
  image-firewall) run_timed_image_target "$target" build_firewall ;;
  images) build_selected_images ;;
esac
