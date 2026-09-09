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

  stage="$BOETTICHER_BUILD_TEMP_DIR/controller-package"
  mkdir -m 0700 "$stage"
  mkdir -p "$stage/bin" "dist/controller"

  GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
    go build -trimpath -o "$stage/bin/boetticher" ./cmd/boetticher
  GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
    go build -trimpath -o "$stage/bin/boetticher-status" ./cmd/boetticher-status
  chmod 0755 "$stage/bin/boetticher" "$stage/bin/boetticher-status"
  cp -R controller "$stage/controller"
  mkdir -p "$stage/controller/proxmox/libexec"
  cp scripts/build-openwrt-firewall.sh "$stage/controller/proxmox/libexec/boetticher-build-openwrt-firewall"
  cp scripts/build-tailnet.sh "$stage/controller/proxmox/libexec/boetticher-build-tailnet"
  cp scripts/build-temp.py "$stage/controller/proxmox/libexec/build-temp.py"
  chmod 0755 "$stage/controller/proxmox/libexec/build-temp.py"
  chmod 0755 "$stage/controller/proxmox/libexec/boetticher-build-tailnet"
  chmod 0755 "$stage/controller/proxmox/libexec/boetticher-build-openwrt-firewall"
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
