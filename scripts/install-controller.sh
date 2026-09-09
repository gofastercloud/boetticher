#!/bin/sh
set -eu

usage() {
  cat <<'EOF'
Usage: install-controller.sh --from-dir PATH --operator USER --confirm-key-login
       install-controller.sh --version VERSION --operator USER --confirm-key-login
EOF
}

die() {
  printf 'Controller installer: FAIL — %s\n' "$1" >&2
  exit 1
}

validate_platform() {
  [ -r /etc/os-release ] || die 'cannot read /etc/os-release'
  # shellcheck disable=SC1091
  . /etc/os-release
  [ "${ID:-}" = 'debian' ] && [ "${VERSION_CODENAME:-}" = 'trixie' ] || die 'controller bootstrap requires Debian 13/Trixie'
  [ "$(dpkg --print-architecture 2>/dev/null)" = 'arm64' ] || die 'controller bootstrap requires an ARM64 userspace'
  [ "$(uname -m)" = 'aarch64' ] || die 'controller bootstrap requires an aarch64 kernel'
  [ -r /proc/device-tree/model ] || die 'controller bootstrap requires Raspberry Pi hardware'
  model=$(tr -d '\000' </proc/device-tree/model)
  case "$model" in
    *Raspberry\ Pi*) ;;
    *) die "controller bootstrap requires Raspberry Pi hardware (found: $model)" ;;
  esac
}

validate_and_extract() {
  archive=$1
  destination=$2
  /usr/bin/python3 - "$archive" "$destination" <<'PY'
import os
import pathlib
import sys
import tarfile

archive, destination = sys.argv[1:]
root = pathlib.Path(destination).resolve()
with tarfile.open(archive, "r:gz") as bundle:
    members = bundle.getmembers()
    for member in members:
        raw = member.name
        if not raw or "\\" in raw or "\x00" in raw:
            raise SystemExit(f"unsafe archive member: {raw!r}")
        path = pathlib.PurePosixPath(raw)
        if not path.parts or path.is_absolute() or ".." in path.parts or "//" in raw or raw.startswith("./") or "/./" in raw:
            raise SystemExit(f"unsafe archive member: {raw!r}")
        if path.parts[0] not in {"bin", "controller", "BUILD_ID"} or (path.parts[0] == "BUILD_ID" and len(path.parts) != 1):
            raise SystemExit(f"unexpected archive member: {raw!r}")
        if member.issym() or member.islnk() or member.isdev() or not (member.isdir() or member.isfile()):
            raise SystemExit(f"unsupported archive member: {raw!r}")
        target = (root / pathlib.Path(*path.parts)).resolve()
        if target != root and root not in target.parents:
            raise SystemExit(f"archive member escapes payload: {raw!r}")
    for member in members:
        target = root / pathlib.Path(*pathlib.PurePosixPath(member.name).parts)
        if member.isdir():
            target.mkdir(mode=0o755, parents=True, exist_ok=True)
            continue
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        source = bundle.extractfile(member)
        if source is None:
            raise SystemExit(f"cannot read archive member: {member.name!r}")
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            while True:
                data = source.read(1024 * 1024)
                if not data:
                    break
                output.write(data)
        os.chmod(target, member.mode & 0o7777)
PY
}

main() {
  from_dir=''
  version=''
  operator=''
  confirm=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --from-dir) [ "$#" -ge 2 ] || die '--from-dir requires a path'; from_dir=$2; shift 2 ;;
      --version) [ "$#" -ge 2 ] || die '--version requires a value'; version=$2; shift 2 ;;
      --operator) [ "$#" -ge 2 ] || die '--operator requires a user'; operator=$2; shift 2 ;;
      --confirm-key-login) confirm=1; shift ;;
      --help|-h) usage; exit 0 ;;
      *) die "unknown option $1" ;;
    esac
  done
  [ "$(id -u)" -eq 0 ] || die 'run as root (for example: sudo sh install.sh ...)'
  [ "$confirm" -eq 1 ] || die '--confirm-key-login is required'
  [ -n "$operator" ] || die '--operator is required'
  case "$operator" in *[!A-Za-z0-9._-]*|'') die 'operator is not a safe account name' ;; esac
  validate_platform
  if [ -n "$from_dir" ] && [ -n "$version" ]; then
    die '--from-dir and --version cannot be combined'
  fi
  [ -n "$from_dir" ] || [ -n "$version" ] || die 'choose --from-dir or --version'
  if [ -n "$version" ]; then
    case "$version" in ''|*[!A-Za-z0-9._-]*) die 'version is not a safe release name' ;; esac
  fi
  id "$operator" >/dev/null 2>&1 || die "operator account does not exist: $operator"

  temporary_download=''
  temporary_sums=''

  exec 9>/run/lock/boetticher-controller-install.lock
  flock -n 9 || die 'another controller installation is already running'
  marker=/var/lib/boetticher/controller/log2ram-installed-boot-id
  if [ -f "$marker" ] && [ "$(cat "$marker")" = "$(cat /proc/sys/kernel/random/boot_id)" ]; then
    die 'log2ram activation requires a reboot before package operations continue'
  fi

  if [ -n "$from_dir" ]; then
    [ -d "$from_dir" ] || die "payload directory does not exist: $from_dir"
    archive="$from_dir/boetticher-controller-linux-arm64.tar.gz"
    sums="$from_dir/SHA256SUMS"
    [ -f "$archive" ] || die 'controller archive is missing'
    [ -f "$sums" ] || die 'SHA256SUMS is missing'
  else
    release_base=${RELEASE_BASE:-}
    [ -n "$release_base" ] || die 'published download path is not configured; use --from-dir for local acceptance'
    case "$release_base" in https://*) ;; *) die 'RELEASE_BASE must be an HTTPS URL' ;; esac
    temporary_download=$(mktemp /tmp/boetticher-controller-download.XXXXXX.tar.gz)
    temporary_sums=$(mktemp /tmp/boetticher-controller-sums.XXXXXX)
    trap 'if [ -n "$temporary_download" ]; then rm -f "$temporary_download"; fi; if [ -n "$temporary_sums" ]; then rm -f "$temporary_sums"; fi' EXIT HUP INT TERM
    archive="$temporary_download"
    sums="$temporary_sums"
    curl --fail --location --silent --show-error --output "$archive" "$release_base/$version/boetticher-controller-linux-arm64.tar.gz"
    curl --fail --location --silent --show-error --output "$sums" "$release_base/$version/SHA256SUMS"
  fi
  expected=$(awk '$2 == "boetticher-controller-linux-arm64.tar.gz" {print $1}' "$sums")
  [ -n "$expected" ] || die 'archive checksum entry is missing'
  printf '%s  %s\n' "$expected" "$archive" | sha256sum --check --status || die 'archive checksum verification failed'

  stage=$(mktemp -d /tmp/boetticher-controller-install.XXXXXX)
  trap 'rm -rf "$stage"; if [ -n "$temporary_download" ]; then rm -f "$temporary_download"; fi; if [ -n "$temporary_sums" ]; then rm -f "$temporary_sums"; fi' EXIT HUP INT TERM
  validate_and_extract "$archive" "$stage/payload" || die 'archive validation or extraction failed'
  payload="$stage/payload"
  [ -f "$payload/BUILD_ID" ] || die 'payload BUILD_ID is missing'
  build_id=$(tr -d '\r\n' <"$payload/BUILD_ID")
  case "$build_id" in ''|*[!A-Za-z0-9._-]*) die 'payload BUILD_ID is invalid' ;; esac
  for required in "$payload/bin/boetticher" "$payload/bin/boetticher-status" "$payload/controller/bootstrap.yml" "$payload/controller/requirements.txt" "$payload/controller/ansible.cfg" "$payload/controller/roles/controller-baseline/files/boetticher-blinkt-driver" "$payload/controller/proxmox/libexec/boetticher-build-openwrt-firewall" "$payload/controller/proxmox/libexec/boetticher-build-tailnet" "$payload/controller/proxmox/libexec/boetticher-firewall-test-host" "$payload/controller/proxmox/libexec/boetticher-host-speedtest" "$payload/controller/proxmox/libexec/boetticher-install-observability-providers" "$payload/controller/proxmox/libexec/boetticher-install-observability-collection" "$payload/controller/proxmox/libexec/boetticher-build-observability-base" "$payload/controller/observability/base/debian.yaml" "$payload/controller/observability/assets/catalog.json" "$payload/controller/observability/assets/victorialogs.service" "$payload/controller/observability/assets/victoriametrics.service" "$payload/controller/observability/assets/grafana.service" "$payload/controller/observability/assets/gatus.service" "$payload/controller/observability/assets/caddy.service" "$payload/controller/observability/assets/bifrost.service" "$payload/controller/observability/assets/gatus.config.yaml" "$payload/controller/observability/assets/grafana-datasource.yaml" "$payload/controller/observability/assets/grafana-dashboard.yaml" "$payload/controller/observability/assets/grafana-overview.json" "$payload/controller/observability/assets/grafana-host-resources.json" "$payload/controller/observability/assets/grafana-service-logs.json" "$payload/controller/observability/assets/grafana-observability-health.json" "$payload/controller/observability/assets/grafana-alerting.yaml" "$payload/controller/observability/bin/gatus" "$payload/controller/observability/bin/bifrost" "$payload/controller/observability/bin/caddy" "$payload/controller/observability/holmes/holmes-runner.py" "$payload/controller/observability/holmes/holmes.yaml" "$payload/controller/observability/holmes/requirements.lock"; do
    [ -f "$required" ] || die "payload file is missing: $required"
  done
  [ -x "$payload/bin/boetticher" ] || die 'payload controller is not executable'

  install_root=/opt/boetticher
  releases="$install_root/releases"
  release="$releases/$build_id"
  mkdir -p "$releases"
  chmod 0755 "$install_root" "$releases"
  if [ -e "$release" ]; then
    cmp -s "$payload/BUILD_ID" "$release/BUILD_ID" || die "release build ID already exists with different contents: $build_id"
    diff -qr "$payload" "$release" >/dev/null || die "release build already exists with different contents: $build_id"
  else
    install_stage="$releases/.staging-$build_id-$$"
    rm -rf "$install_stage"
    mkdir -p "$install_stage"
    cp -R "$payload/bin" "$payload/controller" "$payload/BUILD_ID" "$install_stage/"
    chown -R root:root "$install_stage"
    chmod 0755 "$install_stage/bin/boetticher" "$install_stage/bin/boetticher-status" "$install_stage/controller/roles/controller-baseline/files/boetticher-blinkt-driver" "$install_stage/controller/proxmox/libexec/boetticher-build-openwrt-firewall" "$install_stage/controller/proxmox/libexec/boetticher-build-tailnet" "$install_stage/controller/proxmox/libexec/boetticher-firewall-test-host" "$install_stage/controller/proxmox/libexec/boetticher-host-speedtest" "$install_stage/controller/proxmox/libexec/boetticher-install-observability-providers" "$install_stage/controller/proxmox/libexec/boetticher-install-observability-collection" "$install_stage/controller/proxmox/libexec/boetticher-build-observability-base" "$install_stage/controller/observability/bin/gatus" "$install_stage/controller/observability/bin/bifrost"
    chmod 0644 "$install_stage/BUILD_ID" "$install_stage/controller/requirements.txt" "$install_stage/controller/ansible.cfg" "$install_stage/controller/bootstrap.yml"
    mv "$install_stage" "$release"
  fi
  if { [ -e /usr/local/bin/boetticher ] || [ -L /usr/local/bin/boetticher ]; } && { [ ! -L /usr/local/bin/boetticher ] || [ "$(readlink /usr/local/bin/boetticher)" != "$install_root/current/bin/boetticher" ]; }; then
    die '/usr/local/bin/boetticher already belongs to another installation'
  fi
  if [ -e "$install_root/current" ] || [ -L "$install_root/current" ]; then
    current_target=$(readlink "$install_root/current" 2>/dev/null || true)
    case "$current_target" in
      releases/*|/opt/boetticher/releases/*) ;;
      *) die '/opt/boetticher/current already belongs to another installation' ;;
    esac
  fi
  ln -sfn "$release" "$install_root/current.new"
  mv -Tf "$install_root/current.new" "$install_root/current"
  ln -sfn "$install_root/current/bin/boetticher" /usr/local/bin/boetticher

  env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 update
  env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y --no-install-recommends ca-certificates curl python3 python3-venv python3-apt python3-lgpio gpiod
  venv="$install_root/venv"
  if [ ! -x "$venv/bin/python" ]; then
    python3 -m venv "$venv"
  fi
  requirements="$install_root/current/controller/requirements.txt"
  required_ansible=$(awk -F'==' '/^ansible-core==/ {print $2}' "$requirements")
  installed_ansible=$($venv/bin/ansible-playbook --version 2>/dev/null | awk '/core / {gsub(/[\[\]]/, "", $3); print $3; exit}' || true)
  if [ "$installed_ansible" != "$required_ansible" ]; then
    "$venv/bin/python" -m pip install --disable-pip-version-check --no-input -r "$requirements"
  fi
  "$venv/bin/python" -m pip check
  "$venv/bin/ansible-playbook" --version >/dev/null
  printf '%s\n' "Controller payload: PASS $build_id"
  if /usr/local/bin/boetticher controller bootstrap --operator "$operator" --confirm-key-login; then
    exit 0
  else
    status=$?
    exit "$status"
  fi
}

main "$@"
