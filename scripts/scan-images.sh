#!/bin/sh
set -eu

target=${1:-scan-images}
shift || true
if ! command -v trivy >/dev/null 2>&1; then
  echo "HOLD: Trivy is required for artifact qualification (${target})" >&2
  exit 2
fi

default_scan_names="boetticher-base boetticher-dns-blocky boetticher-logging boetticher-monitoring boetticher-firewall boetticher-portal boetticher-tailnet-router boetticher-litellm boetticher-streamdeck"
case "$target" in
  scan-base) names="boetticher-base" ;;
  scan-dns-blocky) names="boetticher-dns-blocky" ;;
  scan-dns-adguard) names="boetticher-dns-adguard" ;;
  scan-logging) names="boetticher-logging" ;;
  scan-monitoring) names="boetticher-monitoring" ;;
  scan-firewall) names="boetticher-firewall" ;;
  scan-portal) names="boetticher-portal" ;;
  scan-tailnet-router) names="boetticher-tailnet-router" ;;
  scan-litellm) names="boetticher-litellm" ;;
  scan-streamdeck) names="boetticher-streamdeck" ;;
  scan-images)
    names="$*"
    if [ -z "$names" ]; then
      names=$default_scan_names
    fi
    ;;
  *) echo "unknown scan target: $target" >&2; exit 2 ;;
esac
for name in $names; do
  case "$name" in
    boetticher-base|boetticher-dns-blocky|boetticher-dns-adguard|boetticher-logging|boetticher-monitoring|boetticher-firewall|boetticher-portal|boetticher-tailnet-router|boetticher-litellm|boetticher-streamdeck) ;;
    *) echo "unknown selected scan artifact: $name" >&2; exit 2 ;;
  esac
done

root=${BOETTICHER_ARTIFACT_OUTPUT:-generated/artifacts}
evidence_root=${BOETTICHER_EVIDENCE_ROOT:-.}
provenance="$(dirname "$root")/builder-provenance.json"
timing_log=${BOETTICHER_TIMING_LOG:-}
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
    version=0.3.34
  fi
  printf '%s-%s-amd64.tar.zst' "$name" "$version"
}
timing_now_ms() {
  date +%s%3N
}

timing_emit() {
  stage=$1
  duration_ms=$2
  timing_artifact=${3:-}
  line="timing stage=$stage duration_ms=$duration_ms"
  if [ -n "$timing_artifact" ]; then
    line="$line artifact=$timing_artifact"
  fi
  printf '%s\n' "$line"
  if [ -n "${timing_log:-}" ]; then
    printf '%s\n' "$line" >> "$timing_log"
  fi
}

scan_one() {
  name=$1
  scan_started=$(timing_now_ms)
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
  trivy_started=$(timing_now_ms)
  if ! trivy fs --scanners vuln,secret --skip-db-update --format json --list-all-pkgs --output "$report" "$scan_root"; then
    exit 2
  fi
  if ! trivy convert --scanners vuln,secret --format table --output "$summary" "$report"; then
    exit 2
  fi
  if [ ! -s "$summary" ]; then
    echo "HOLD: Trivy human-readable summary is empty for $name" >&2
    exit 2
  fi
  if ! trivy convert --format cyclonedx --output "$sbom" "$report"; then
    exit 2
  fi
  trivy_finished=$(timing_now_ms)
  timing_emit "artifact_trivy_scan" "$((trivy_finished - trivy_started))" "$name"
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
    boetticher-tailnet-router) module=tailnet-router ;;
    boetticher-litellm) module=litellm ;;
    boetticher-streamdeck) module=streamdeck ;;
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
  scan_finished=$(timing_now_ms)
  timing_emit "artifact_qualification" "$((scan_finished - scan_started))" "$name"
}

launch_scan_worker() {
  worker_name=$1
  worker_log="$scan_log_root/$worker_name.log"
  worker_timing="$scan_log_root/$worker_name.timing"
  mkdir -p "$scan_log_root"
  (
    timing_log="$worker_timing"
    scan_one "$worker_name"
  ) >"$worker_log" 2>&1 &
  worker_pid=$!
}

append_scan_timings() {
  worker_timing=$1
  if [ -f "$worker_timing" ]; then
    cat "$worker_timing"
    if [ -n "$timing_log" ]; then
      cat "$worker_timing" >> "$timing_log"
    fi
  fi
}

wait_scan_worker() {
  worker_pid=$1
  worker_name=$2
  worker_log=$3
  worker_timing=$4
  if wait "$worker_pid"; then
    worker_status=0
  else
    worker_status=$?
  fi
  append_scan_timings "$worker_timing"
  if [ "$worker_status" -ne 0 ]; then
    cat "$worker_log" >&2
  fi
  return "$worker_status"
}

run_selected_scans() {
  scan_all_started=$(timing_now_ms)
  timing_log="$root/scan-timings.log"
  : > "$timing_log"
  scan_db_started=$(timing_now_ms)
  if ! trivy fs --download-db-only; then
    echo "HOLD: Trivy vulnerability database could not be prepared" >&2
    return 1
  fi
  scan_db_finished=$(timing_now_ms)
  timing_emit "artifact_trivy_db_update" "$((scan_db_finished - scan_db_started))"
  scan_log_root=${BOETTICHER_SCAN_LOG_ROOT:-$(dirname "$root")/scan-logs}
  mkdir -p "$scan_log_root"
  failed=0
  pid_a=
  pid_b=
  for selected_name in $names; do
    if [ -n "$pid_a" ] && [ -n "$pid_b" ]; then
      if ! wait_scan_worker "$pid_a" "$name_a" "$log_a" "$timing_a"; then
        failed=1
      fi
      pid_a=
      if [ "$failed" -ne 0 ]; then
        break
      fi
    fi
    launch_scan_worker "$selected_name"
    if [ -z "$pid_a" ]; then
      pid_a=$worker_pid
      name_a=$worker_name
      log_a=$worker_log
      timing_a=$worker_timing
    else
      pid_b=$worker_pid
      name_b=$worker_name
      log_b=$worker_log
      timing_b=$worker_timing
    fi
  done
  if [ -n "$pid_a" ]; then
    if ! wait_scan_worker "$pid_a" "$name_a" "$log_a" "$timing_a"; then
      failed=1
    fi
  fi
  if [ -n "$pid_b" ]; then
    if ! wait_scan_worker "$pid_b" "$name_b" "$log_b" "$timing_b"; then
      failed=1
    fi
  fi
  scan_all_finished=$(timing_now_ms)
  timing_emit "artifact_qualification_all" "$((scan_all_finished - scan_all_started))"
  if [ "$failed" -ne 0 ]; then
    return 1
  fi
}

run_selected_scans
