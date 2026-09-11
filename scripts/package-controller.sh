#!/bin/sh
set -eu

if [ "${BOETTICHER_BUILD_TEMP_ACTIVE:-0}" != 1 ] || [ ! -f "${BOETTICHER_BUILD_TEMP_DIR:-}/.boetticher-build-token" ] || [ ! -f "${BOETTICHER_BUILD_TEMP_LOCK:-}" ] || ! grep -F -x -q -- "${BOETTICHER_BUILD_TEMP_TOKEN:-}" "${BOETTICHER_BUILD_TEMP_DIR:-}/.boetticher-build-token"; then
  keep_flag=
  if [ "${1:-}" = --keep-build-files ]; then
    keep_flag=--keep-build-files
    shift
  fi
  script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
  exec python3 "$script_dir/build-temp.py" run "${BOETTICHER_BUILD_TEMP_ROOT:-${TMPDIR:-/var/tmp}/boetticher-builds}" $keep_flag -- "$0" "$@"
fi

main() {
  build_id=${1:?Usage: package-controller.sh BUILD_ID}
  case "$build_id" in
    ''|*[!A-Za-z0-9._-]*)
      echo "Invalid build ID" >&2
      exit 1
      ;;
  esac

  go_bin=${BOETTICHER_GO_BIN:-$(command -v go || true)}
  [ -n "$go_bin" ] && [ -x "$go_bin" ] || { echo 'Go toolchain is unavailable; set BOETTICHER_GO_BIN to Go 1.26.6' >&2; exit 1; }
  "$go_bin" version | grep -Eq 'go1\.26\.6([[:space:]]|$)' || { echo 'Controller packaging requires Go 1.26.6; set BOETTICHER_GO_BIN' >&2; exit 1; }
  export GOCACHE="${GOCACHE:-$($go_bin env GOCACHE)}" GOMODCACHE="${GOMODCACHE:-$($go_bin env GOMODCACHE)}"

  stage="$BOETTICHER_BUILD_TEMP_DIR/controller-package"
  mkdir -m 0700 "$stage"
  mkdir -p "$stage/bin" "dist/controller"

  GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
    go build -trimpath -o "$stage/bin/boetticher" ./cmd/boetticher
  GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
    go build -trimpath -o "$stage/bin/boetticher-status" ./cmd/boetticher-status
  chmod 0755 "$stage/bin/boetticher" "$stage/bin/boetticher-status"
  ARRSTACK_SOURCE_ARCHIVE=${ARRSTACK_SOURCE_ARCHIVE:?ARRSTACK_SOURCE_ARCHIVE must point to the reviewed upstream tarball} \
    sh scripts/build-arrstack.sh "$stage/bin/arrstack"
  chmod 0755 "$stage/bin/arrstack"
  cp -R controller "$stage/controller"
  mkdir -p "$stage/controller/proxmox/libexec"
  cp scripts/build-openwrt-firewall.sh "$stage/controller/proxmox/libexec/boetticher-build-openwrt-firewall"
  cp scripts/build-tailnet.sh "$stage/controller/proxmox/libexec/boetticher-build-tailnet"
  cp scripts/build-arrstack-vm.sh "$stage/controller/proxmox/libexec/boetticher-build-arrstack-vm"
  cp scripts/build-temp.py "$stage/controller/proxmox/libexec/build-temp.py"
  cp scripts/cleanup-controller-storage.sh "$stage/controller/proxmox/libexec/cleanup-controller-storage.sh"
  chmod 0755 "$stage/controller/proxmox/libexec/build-temp.py" "$stage/controller/proxmox/libexec/cleanup-controller-storage.sh"
  chmod 0755 "$stage/controller/proxmox/libexec/boetticher-build-tailnet"
  chmod 0755 "$stage/controller/proxmox/libexec/boetticher-build-arrstack-vm"
  chmod 0755 "$stage/controller/proxmox/libexec/boetticher-build-openwrt-firewall"

  mkdir -p "$stage/controller/observability/bin"
  catalog_value() {
    key=$1
    field=$2
    awk -F'"' -v key="$key" -v field="$field" '$2 == key { for (i = 1; i <= NF; i++) if ($i == field) { print $(i + 2); exit } }' internal/observability/assets/catalog.json
  }
  gatus_url=$(catalog_value gatus url)
  gatus_sha=$(catalog_value gatus sha256)
  case "$gatus_url" in https://*) ;; *) echo 'gatus catalog URL is not HTTPS' >&2; exit 1 ;; esac
  case "$gatus_sha" in ''|*[!0-9a-fA-F]*) echo 'gatus catalog checksum is invalid' >&2; exit 1 ;; esac
  [ "${#gatus_sha}" -eq 64 ] || { echo 'gatus catalog checksum is invalid' >&2; exit 1; }
  build_cache=${BOETTICHER_OBSERVABILITY_BUILD_CACHE:-/tmp/boetticher-observability-cache}
  mkdir -p "$build_cache"
  gatus_archive="$build_cache/gatus-${gatus_sha}.tar.gz"
  gatus_temporary="$gatus_archive.tmp.$$"
  trap 'rm -rf "$stage" "$gatus_temporary"' EXIT HUP INT TERM
  if [ ! -f "$gatus_archive" ] || [ "$(sha256sum "$gatus_archive" | awk '{print $1}')" != "$gatus_sha" ]; then
    rm -f "$gatus_temporary"
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --max-time 120 --output "$gatus_temporary" "$gatus_url"
    [ "$(sha256sum "$gatus_temporary" | awk '{print $1}')" = "$gatus_sha" ] || { rm -f "$gatus_temporary"; echo 'gatus source checksum verification failed' >&2; exit 1; }
    mv -f "$gatus_temporary" "$gatus_archive"
  fi
  gatus_source="$stage/gatus-source"
  mkdir -p "$gatus_source"
  tar -tzf "$gatus_archive" | awk 'BEGIN { bad=0 } { raw=$0; sub(/\/$/,"",raw); if (raw == "" || raw ~ /^\// || raw ~ /(^|\/)\.\.($|\/)/ || raw ~ /\\/) { print "unsafe gatus source member: " $0 > "/dev/stderr"; bad=1 } } END { exit bad }'
  tar -xzf "$gatus_archive" -C "$gatus_source" --strip-components=1 --no-same-owner --no-same-permissions
  (cd "$gatus_source" && GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOCACHE="$GOCACHE" GOMODCACHE="$GOMODCACHE" "$go_bin" build -trimpath -ldflags='-s -w' -o "$stage/controller/observability/bin/gatus" .)
  chmod 0755 "$stage/controller/observability/bin/gatus"
  GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$go_bin" build -trimpath -ldflags='-s -w' -o "$stage/controller/observability/bin/bifrost" ./cmd/boetticher-bifrost
  chmod 0755 "$stage/controller/observability/bin/bifrost"
  GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$go_bin" build -trimpath -ldflags='-s -w' -o "$stage/controller/observability/bin/boetticher-incidentd" ./cmd/boetticher-incidentd
  chmod 0755 "$stage/controller/observability/bin/boetticher-incidentd"
  (cd "$stage/controller/observability/caddy" && GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$go_bin" build -trimpath -ldflags='-s -w' -o "$stage/controller/observability/bin/caddy" .)
  chmod 0755 "$stage/controller/observability/bin/caddy"
  cp -R internal/observability/assets "$stage/controller/observability/"
  mkdir -p "$stage/controller/observability/holmes"
  cp controller/observability/holmes/holmes-runner.py controller/observability/holmes/holmes.yaml "$stage/controller/observability/holmes/"
  cp controller/observability/holmes/requirements.lock "$stage/controller/observability/holmes/requirements.lock"
  chmod 0644 "$stage/controller/observability/holmes/holmes-runner.py" "$stage/controller/observability/holmes/holmes.yaml" "$stage/controller/observability/holmes/requirements.lock"
  cp scripts/install-observability-providers.sh "$stage/controller/proxmox/libexec/boetticher-install-observability-providers"
  chmod 0755 "$stage/controller/proxmox/libexec/boetticher-install-observability-providers"
  cp scripts/build-observability-base.sh "$stage/controller/proxmox/libexec/boetticher-build-observability-base"
  chmod 0755 "$stage/controller/proxmox/libexec/boetticher-build-observability-base"
  cp scripts/install-observability-collection.sh "$stage/controller/proxmox/libexec/boetticher-install-observability-collection"
  chmod 0755 "$stage/controller/proxmox/libexec/boetticher-install-observability-collection"
  mkdir -p "$stage/controller/observability/base"
  cp images/base/debian.yaml "$stage/controller/observability/base/debian.yaml"
	GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
	  go build -trimpath -o "$stage/controller/proxmox/libexec/boetticher-host-speedtest" ./cmd/boetticher-host-speedtest
	GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
	  go build -trimpath -o "$stage/controller/proxmox/libexec/boetticher-firewall-test-host" ./cmd/boetticher-firewall-test-host
	chmod 0755 "$stage/controller/proxmox/libexec/boetticher-host-speedtest" "$stage/controller/proxmox/libexec/boetticher-firewall-test-host"
  printf '%s\n' "$build_id" >"$stage/BUILD_ID"

    COPYFILE_DISABLE=1 tar -C "$stage" -czf dist/controller/boetticher-controller-linux-arm64.tar.gz \
        bin controller BUILD_ID
  cp scripts/install-controller.sh dist/controller/install.sh
  chmod 0755 dist/controller/install.sh
  (
    cd dist/controller
    sha256sum boetticher-controller-linux-arm64.tar.gz >SHA256SUMS
  )
  printf '%s\n' "controller payload: dist/controller/boetticher-controller-linux-arm64.tar.gz build=$build_id"
}

main "$@"
