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
  scan-images) names="boetticher-base boetticher-dns-blocky boetticher-logging boetticher-monitoring boetticher-firewall boetticher-portal" ;;
  *) echo "unknown scan target: $target" >&2; exit 2 ;;
esac

root=${BOETTICHER_ARTIFACT_OUTPUT:-generated/artifacts}
evidence_root=${BOETTICHER_EVIDENCE_ROOT:-.}
provenance="$(dirname "$root")/builder-provenance.json"
scan_root=
mounted=0
cleanup_scan_root() {
  if [ "$mounted" -eq 1 ] && [ -n "${scan_root:-}" ]; then
    guestunmount "$scan_root" >/dev/null 2>&1 || true
    mounted=0
  fi
  if [ -n "${scan_root:-}" ]; then
    rm -rf -- "$scan_root"
  fi
}
trap cleanup_scan_root EXIT HUP INT TERM

artifact_filename() {
  name=$1
  version=1.0.0
  if [ "$name" = boetticher-base ]; then
    version=0.3.25
  fi
  printf '%s-%s-amd64.tar.zst' "$name" "$version"
}
for name in $names; do
  artifact="$root/$name/$(artifact_filename "$name")"
  scan_root="$root/.scan-root/$name"
  mounted=0
  if [ "$name" = boetticher-firewall ]; then
    artifact="$root/$name/boetticher-firewall-1.0.0-amd64.qcow2"
  fi
  report="$root/$name/trivy.json"
  summary="$root/$name/trivy.txt"
  manifest="$root/$name/package-manifest.txt"
  sbom="$root/$name/sbom.json"
  if [ ! -f "$artifact" ]; then
    echo "HOLD: artifact is not built: $artifact" >&2
    exit 2
  fi
  provenance_arg=
  if [ -s "$provenance" ]; then
    cp "$provenance" "$root/$name/builder-provenance.json"
    provenance_arg="-provenance $root/$name/builder-provenance.json"
  fi
  mkdir -p "$(dirname "$report")"
  if [ ! -s "$manifest" ]; then
    echo "HOLD: package manifest is missing for $name: $manifest" >&2
    exit 2
  fi
  rm -rf "$scan_root"
  mkdir -p "$scan_root"
  if [ "$name" = boetticher-firewall ]; then
    for tool in guestmount guestunmount; do
      if ! command -v "$tool" >/dev/null 2>&1; then
        echo "HOLD: $tool is required to scan the firewall rootfs" >&2
        exit 2
      fi
    done
    guestmount -a "$artifact" -i --ro "$scan_root"
    mounted=1
  else
    tar --zstd -xf "$artifact" -C "$scan_root"
  fi
  # Keep unfixed findings in the report. Policy evaluation is performed by the
  # qualification command after this raw, machine-readable scan completes.
  if ! trivy fs --scanners vuln,secret --format json --output "$report" "$scan_root"; then
    exit 2
  fi
  if ! trivy fs --scanners vuln,secret --format table --output "$summary" "$scan_root"; then
    exit 2
  fi
  if [ ! -s "$summary" ]; then
    echo "HOLD: Trivy human-readable summary is empty for $name" >&2
    exit 2
  fi
  if ! trivy fs --scanners vuln,secret --format cyclonedx --output "$sbom" "$scan_root"; then
    exit 2
  fi
  if [ "$mounted" -eq 1 ]; then
    guestunmount "$scan_root"
    mounted=0
  fi
  cleanup_scan_root
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
      $provenance_arg \
      -evidence-root "$evidence_root" -module "$module" -provider "$provider"
  else
    GOCACHE=${GOCACHE:-/tmp/boetticher-gocache} go run ./cmd/qualify-artifact \
      -artifact "$artifact" -report "$report" -manifest "$manifest" -sbom "$sbom" \
      $provenance_arg \
      -evidence-root "$evidence_root" -module "$module"
  fi
done
