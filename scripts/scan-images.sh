#!/bin/sh
set -eu

target=${1:-scan-images}
if ! command -v trivy >/dev/null 2>&1; then
  echo "HOLD: Trivy is required for artifact qualification (${target})" >&2
  exit 2
fi

case "$target" in
  scan-base) names="boetticher-base" ;;
  scan-dns-blocky) names="boetticher-dns-blocky" ;;
  scan-dns-adguard) names="boetticher-dns-adguard" ;;
  scan-logging) names="boetticher-logging" ;;
  scan-monitoring) names="boetticher-monitoring" ;;
  scan-firewall) names="boetticher-firewall" ;;
  scan-portal) names="boetticher-portal" ;;
  scan-images) names="boetticher-base boetticher-dns-blocky boetticher-dns-adguard boetticher-logging boetticher-monitoring boetticher-firewall boetticher-portal" ;;
  *) echo "unknown scan target: $target" >&2; exit 2 ;;
esac

root=${BOETTICHER_ARTIFACT_OUTPUT:-generated/artifacts}
for name in $names; do
  artifact="$root/$name/$name.tar.zst"
  report="$root/$name/trivy.json"
  manifest="$root/$name/package-manifest.txt"
  sbom="$root/$name/sbom.json"
  if [ ! -f "$artifact" ]; then
    echo "HOLD: artifact is not built: $artifact" >&2
    exit 2
  fi
  mkdir -p "$(dirname "$report")"
  tar -tf "$artifact" > "$manifest"
  # Keep unfixed findings in the report. Policy evaluation is performed by the
  # qualification command after this raw, machine-readable scan completes.
  trivy fs --scanners vuln,secret --format json --output "$report" "$artifact"
  trivy fs --scanners vuln,secret --format cyclonedx --output "$sbom" "$artifact"
  module=$name
  provider=""
  case "$name" in
    boetticher-dns-blocky) module=dns; provider=blocky ;;
    boetticher-dns-adguard) module=dns; provider=adguard ;;
    boetticher-base) module=base ;;
    boetticher-logging) module=logging ;;
    boetticher-monitoring) module=monitoring ;;
    boetticher-firewall) module=firewall ;;
    boetticher-portal) module=portal ;;
  esac
  if [ -n "$provider" ]; then
    GOCACHE=${GOCACHE:-/tmp/boetticher-gocache} go run ./cmd/qualify-artifact \
      -artifact "$artifact" -report "$report" -manifest "$manifest" -sbom "$sbom" \
      -evidence-root "$root" -module "$module" -provider "$provider"
  else
    GOCACHE=${GOCACHE:-/tmp/boetticher-gocache} go run ./cmd/qualify-artifact \
      -artifact "$artifact" -report "$report" -manifest "$manifest" -sbom "$sbom" \
      -evidence-root "$root" -module "$module"
  fi
done
