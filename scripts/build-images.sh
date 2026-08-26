#!/bin/sh
set -eu

target=${1:-images}
case "$(uname -s)" in
  Linux) ;;
  *) echo "HOLD: appliance construction requires the supported Linux builder environment; use boetticher bootstrap on macOS" >&2; exit 2 ;;
esac

if ! command -v distrobuilder >/dev/null 2>&1; then
  echo "HOLD: distrobuilder is required for real appliance construction" >&2
  exit 2
fi

if [ -z "${BOETTICHER_IMAGE_BUILD_COMMAND:-}" ]; then
  echo "HOLD: the release builder command is not configured; use the bootstrap Linux builder implementation" >&2
  exit 2
fi
exec sh -c "$BOETTICHER_IMAGE_BUILD_COMMAND" -- "$target"
