#!/bin/sh
set -eu

main() {
  build_id=${1:?Usage: package-controller.sh BUILD_ID}
  case "$build_id" in
    ''|*[!A-Za-z0-9._-]*)
      echo "Invalid build ID" >&2
      exit 1
      ;;
  esac

  stage=$(mktemp -d /tmp/boetticher-controller-package.XXXXXX)
  trap 'rm -rf "$stage"' EXIT HUP INT TERM
  mkdir -p "$stage/bin" "dist/controller"

  GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
    go build -trimpath -o "$stage/bin/boetticher" ./cmd/boetticher
  chmod 0755 "$stage/bin/boetticher"
  cp -R controller "$stage/controller"
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
