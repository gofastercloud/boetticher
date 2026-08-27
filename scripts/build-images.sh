#!/bin/sh
set -eu

# Linux-native appliance construction. The builder VM and a Linux controller
# execute this same script; macOS controllers intentionally stop before any
# image tooling is attempted.
target=${1:-images}
case "$target" in
  image-base|image-dns-blocky|image-dns-adguard|image-logging|image-monitoring|image-portal|image-firewall|images) ;;
  *) echo "unknown image target: $target" >&2; exit 2 ;;
esac

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

for tool in mmdebstrap tar zstd sha256sum curl chroot go jq; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "HOLD: required Linux image-build tool is unavailable: $tool" >&2
    exit 2
  fi
done

output_root=${BOETTICHER_ARTIFACT_OUTPUT:-generated/artifacts}
work_root=${BOETTICHER_IMAGE_WORK:-/tmp/boetticher-image-build}
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
zabbix_release_url=https://repo.zabbix.com/zabbix/7.0/debian/pool/main/z/zabbix-release/zabbix-release_7.0-5+debian13_all.deb
zabbix_release_sha256=4a926b8815cdefddc31558fe622676730a3987610f75d5af0d4024809d21dd43
zabbix_package_version=1:7.0.30-1+debian13
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
    --arg boetticher_version 0.3.29 \
    '{platform:$platform,input_image:$input_image,kernel:$kernel,go:$go,trivy:$trivy,mmdebstrap:$mmdebstrap,libguestfs:$libguestfs,qemu_img:$qemu_img,architecture:$architecture,boetticher_version:$boetticher_version}' \
    > "$provenance_path"
  chmod 0644 "$provenance_path"
}

write_builder_provenance

cleanup() {
  if [ -n "${ACTIVE_ROOT:-}" ] && [ -d "$ACTIVE_ROOT" ]; then
    umount -R "$ACTIVE_ROOT/dev" 2>/dev/null || true
    umount -R "$ACTIVE_ROOT/proc" 2>/dev/null || true
    umount -R "$ACTIVE_ROOT/sys" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

rootfs_for() {
  printf '%s/%s-rootfs' "$work_root" "$1"
}

artifact_for() {
	name=$1
	version=1.0.0
	if [ "$name" = boetticher-base ]; then
		version=0.3.29
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
  mkdir -p "$rootfs/etc/boetticher" "$rootfs/usr/lib/boetticher" "$rootfs/run/boetticher/bootstrap"
  install -D -m 0644 images/base/runtime/journal-upload.conf "$rootfs/etc/systemd/journal-upload.conf"
  install -D -m 0440 images/base/runtime/boetticher.sudoers "$rootfs/etc/sudoers.d/boetticher"
  install -D -m 0755 images/base/first-boot/boetticher-first-boot.sh "$rootfs/usr/lib/boetticher/boetticher-first-boot.sh"
  install -D -m 0644 images/base/first-boot/boetticher-first-boot.service "$rootfs/etc/systemd/system/boetticher-first-boot.service"
  install -D -m 0755 images/base/runtime/install-runtime-state.sh "$rootfs/usr/lib/boetticher/install-runtime-state"
  chroot "$rootfs" useradd --create-home --shell /bin/bash labadmin
  chroot "$rootfs" usermod --append --groups sudo labadmin
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
    sqlite3

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

install_zabbix() {
  rootfs=$1
  release="$work_root/zabbix-release_7.0-5+debian13_all.deb"
  if [ ! -f "$release" ]; then
    curl --fail --location --silent --show-error --output "$release" "$zabbix_release_url"
  fi
  printf '%s  %s\n' "$zabbix_release_sha256" "$release" | sha256sum --check --status
  install -D -m 0644 "$release" "$rootfs/tmp/zabbix-release.deb"
  mount --bind /dev "$rootfs/dev"
  mount -t proc proc "$rootfs/proc"
  mount --rbind /sys "$rootfs/sys"
  chroot "$rootfs" dpkg --install /tmp/zabbix-release.deb
  umount -R "$rootfs/dev" || true
  umount -R "$rootfs/proc" || true
  umount -R "$rootfs/sys" || true
  install_packages "$rootfs" \
    "zabbix-server-pgsql=$zabbix_package_version" \
    "zabbix-frontend-php=$zabbix_package_version" \
    "zabbix-nginx-conf=$zabbix_package_version" \
    "zabbix-sql-scripts=$zabbix_package_version" \
    "zabbix-agent2=$zabbix_package_version" \
    php-pgsql postgresql nginx
  installed_version=$(chroot "$rootfs" dpkg-query -W -f='${Version}' zabbix-server-pgsql)
  if [ "$installed_version" != "$zabbix_package_version" ]; then
    echo "HOLD: unexpected Zabbix server package version: $installed_version" >&2
    return 2
  fi
  if ! chroot "$rootfs" /usr/sbin/zabbix_server --version 2>&1 | grep -q '7\.0\.30'; then
    echo "HOLD: Zabbix executable is not the qualified 7.0.30 release" >&2
    return 2
  fi
  chroot "$rootfs" dpkg --purge zabbix-release >/dev/null 2>&1 || true
  rm -f "$rootfs/tmp/zabbix-release.deb"
}

package_lxc() {
  name=$1
  rootfs=$(rootfs_for "$name")
  destination="$output_root/$name"
  mkdir -p "$destination"
  ./scripts/smoke-appliance.sh "$name" "$rootfs"
  chroot "$rootfs" dpkg-query -W -f='${binary:Package}\t${Version}\n' | sort > "$destination/package-manifest.txt"
  tar --numeric-owner --xattrs --acls -C "$rootfs" -cf - . | zstd -T0 -19 -o "$(artifact_for "$name")"
  sha256sum "$(artifact_for "$name")" > "$destination/content.sha256"
}

build_base() {
  rootfs=$(rootfs_for boetticher-base)
  create_base_rootfs "$rootfs"
  write_artifact_identity "$rootfs" base
  package_lxc boetticher-base
}

build_dns_blocky() {
  rootfs=$(prepare_rootfs boetticher-dns-blocky)
  install_powerdns "$rootfs"
  install_packages "$rootfs" chrony
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
  rootfs=$(prepare_rootfs boetticher-logging)
  install_packages "$rootfs" systemd-journal-remote
  write_artifact_identity "$rootfs" logging
  package_lxc boetticher-logging
}

build_monitoring() {
  rootfs=$(prepare_rootfs boetticher-monitoring)
  install_zabbix "$rootfs"
  install -D -m 0755 images/monitoring/runtime/prepare-zabbix-config.sh "$rootfs/usr/lib/boetticher/prepare-zabbix-config"
  mkdir -p "$rootfs/etc/systemd/system/zabbix-server.service.d"
  printf '%s\n' '[Service]' 'LoadCredentialEncrypted=zabbix-db-password:/var/lib/boetticher/credentials/zabbix-db-password.cred' 'ExecStartPre=/usr/lib/boetticher/prepare-zabbix-config' 'ExecStart=' 'ExecStart=/usr/sbin/zabbix_server -c /run/zabbix/zabbix_server.conf' > "$rootfs/etc/systemd/system/zabbix-server.service.d/boetticher-credentials.conf"
  write_artifact_identity "$rootfs" monitoring
  package_lxc boetticher-monitoring
}

build_portal() {
  rootfs=$(prepare_rootfs boetticher-portal)
  install_packages "$rootfs" nginx
  write_artifact_identity "$rootfs" portal
  package_lxc boetticher-portal
}

build_firewall() {
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
  zabbix_release="$work_root/zabbix-release_7.0-5+debian13_all.deb"
  if [ ! -f "$zabbix_release" ]; then
    curl --fail --location --silent --show-error --output "$zabbix_release" "$zabbix_release_url"
  fi
  printf '%s  %s\n' "$zabbix_release_sha256" "$zabbix_release" | sha256sum --check --status
  image="$destination/boetticher-firewall-1.0.0-amd64.qcow2"
  artifact_identity="$work_root/firewall-artifact.json"
  go run ./cmd/artifact-identity -module firewall > "$artifact_identity"
  cp "$input" "$image"
  virt-customize -a "$image" \
    --network \
    --upload images/base/runtime/debian-snapshot.sources:/etc/apt/sources.list.d/boetticher-debian.sources \
    --run-command 'rm -f /etc/apt/sources.list.d/debian.sources /etc/apt/sources.list; apt-get -o Acquire::Check-Valid-Until=false update' \
    --run-command 'DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends nftables kea-dhcp4-server kea-dhcp-ddns-server dnsmasq chrony openssh-server sudo cloud-init systemd-journal-remote curl jq openssl qemu-guest-agent' \
    --upload "$zabbix_release:/tmp/zabbix-release.deb" \
    --run-command 'dpkg --install /tmp/zabbix-release.deb' \
    --run-command 'apt-get -o Acquire::Check-Valid-Until=false update' \
    --run-command "DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends zabbix-agent2=$zabbix_package_version" \
    --run-command 'dpkg --purge zabbix-release >/dev/null 2>&1 || true' \
    --run-command 'rm -f /tmp/zabbix-release.deb; apt-get clean; rm -rf /var/lib/apt/lists/*' \
    --mkdir /etc/boetticher \
    --mkdir /usr/lib/boetticher \
    --mkdir /var/lib/boetticher/identity/ssh \
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
    --upload images/base/runtime/boetticher.sudoers:/etc/sudoers.d/boetticher \
    --upload "$artifact_identity:/usr/lib/boetticher/artifact.json" \
    --upload images/firewall/runtime/forwarding.conf:/etc/sysctl.d/boetticher-forwarding.conf \
    --run-command 'useradd --create-home --shell /bin/bash labadmin' \
    --run-command 'usermod --append --groups sudo labadmin' \
    --run-command 'passwd --lock labadmin' \
    --run-command 'chown labadmin:labadmin /tmp/boetticher-ansible && chmod 0700 /tmp/boetticher-ansible' \
    --run-command 'chmod 0440 /etc/sudoers.d/boetticher' \
    --run-command 'rm -f /etc/ssh/ssh_host_* /root/.ssh/authorized_keys /home/labadmin/.ssh/authorized_keys' \
    --run-command 'visudo -cf /etc/sudoers' \
    --run-command 'dpkg-query -W -f="${binary:Package}\\t${Version}\\n" | sort > /var/lib/boetticher/package-manifest.txt' \
    --run-command 'systemctl enable boetticher-first-boot.service' \
    --run-command 'if systemctl list-unit-files systemd-networkd-wait-online.service >/dev/null 2>&1; then systemctl disable --now systemd-networkd-wait-online.service; fi'
  sha256sum "$image" > "$destination/content.sha256"
  virt-cat -a "$image" /var/lib/boetticher/package-manifest.txt > "$destination/package-manifest.txt"
  ./scripts/smoke-firewall-image.sh "$image"
}

case "$target" in
  image-base) build_base ;;
  image-dns-blocky) [ -f "$(artifact_for boetticher-base)" ] || build_base; build_dns_blocky ;;
  image-logging) [ -f "$(artifact_for boetticher-base)" ] || build_base; build_logging ;;
  image-monitoring) [ -f "$(artifact_for boetticher-base)" ] || build_base; build_monitoring ;;
  image-portal) [ -f "$(artifact_for boetticher-base)" ] || build_base; build_portal ;;
  image-dns-adguard) echo "HOLD: AdGuard provider qualification is outside the default Blocky readiness tranche" >&2; exit 2 ;;
  image-firewall) build_firewall ;;
  images)
    build_base
    build_dns_blocky
    build_logging
    build_monitoring
    build_portal
    build_firewall
    ;;
esac
