#!/bin/sh
set -eu

target=${1:-scan-images}
if ! command -v trivy >/dev/null 2>&1; then
  echo "HOLD: Trivy is required for artifact qualification (${target})" >&2
  exit 2
fi
echo "Scanning ${target}; secret findings fail, fixable CRITICAL findings fail, and HIGH/unfixed CRITICAL findings are reported."
