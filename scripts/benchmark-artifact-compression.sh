#!/bin/sh
set -eu

# Measure packaging treatments without changing the qualified artifact path.
# The input rootfs must already be produced by the normal builder; this script
# is an experiment harness, not an alternate qualification path.
if [ "$#" -ne 2 ]; then
  echo "usage: $0 ROOTFS OUTPUT_DIR" >&2
  exit 2
fi

rootfs=$1
output=$2
if [ ! -d "$rootfs" ]; then
  echo "HOLD: artifact benchmark rootfs is not a directory: $rootfs" >&2
  exit 2
fi
artifact_name=${BOETTICHER_BENCHMARK_ARTIFACT:-$(basename "$rootfs")}
case "$artifact_name" in
  ''|*[!A-Za-z0-9._-]*)
    echo "HOLD: benchmark artifact name contains unsupported characters" >&2
    exit 2
    ;;
esac

for tool in awk du find sha256sum stat tar wc zstd; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "HOLD: required artifact benchmark tool is unavailable: $tool" >&2
    exit 2
  fi
done
if [ ! -x /usr/bin/time ]; then
  echo "HOLD: required artifact benchmark tool is unavailable: /usr/bin/time" >&2
  exit 2
fi

mkdir -p "$output"
temporary_root=$(mktemp -d "$output/.artifact-benchmark.XXXXXX")
cleanup() {
  rm -rf -- "$temporary_root"
}
trap cleanup EXIT HUP INT TERM

export LC_ALL=C
rootfs_apparent_bytes=$(du -sx --apparent-size --block-size=1 "$rootfs" | awk '{print $1}')
rootfs_allocated_bytes=$(du -sx --block-size=1 "$rootfs" | awk '{print $1}')
rootfs_file_count=$(find "$rootfs" -xdev -type f -printf '.' | wc -c | tr -d ' ')
zstd_levels=${BOETTICHER_BENCHMARK_ZSTD_LEVELS:-"1 3 6 9 19"}
include_plain=${BOETTICHER_BENCHMARK_INCLUDE_PLAIN:-1}
case "$include_plain" in
  0|1) ;;
  *) echo "HOLD: BOETTICHER_BENCHMARK_INCLUDE_PLAIN must be 0 or 1" >&2; exit 2 ;;
esac

emit_result() {
  codec=$1
  level=$2
  archive=$3
  timing=$4
  compressed_bytes=$(stat -c '%s' "$archive")
  wall_ms=$(awk '{printf "%d", $1 * 1000}' "$timing")
  user_ms=$(awk '{printf "%d", $2 * 1000}' "$timing")
  system_ms=$(awk '{printf "%d", $3 * 1000}' "$timing")
  compression_ratio=$(awk -v raw="$rootfs_apparent_bytes" -v compressed="$compressed_bytes" 'BEGIN { if (compressed > 0) printf "%.6f", raw / compressed; else print "0" }')
  printf 'measurement stage=artifact_benchmark artifact=%s codec=%s level=%s rootfs_apparent_bytes=%s rootfs_allocated_bytes=%s file_count=%s compressed_bytes=%s duration_ms=%s cpu_user_ms=%s cpu_system_ms=%s compression_ratio=%s\n' \
    "$artifact_name" "$codec" "$level" "$rootfs_apparent_bytes" "$rootfs_allocated_bytes" "$rootfs_file_count" "$compressed_bytes" "$wall_ms" "$user_ms" "$system_ms" "$compression_ratio"
}

if [ "$include_plain" -eq 1 ]; then
  plain_archive="$output/$artifact_name-plain.tar"
  plain_timing="$temporary_root/plain.time"
  /usr/bin/time -f '%e %U %S' -o "$plain_timing" \
    tar --numeric-owner --xattrs --acls -C "$rootfs" -cf "$plain_archive" .
  emit_result tar none "$plain_archive" "$plain_timing"
fi

for level in $zstd_levels; do
  case "$level" in
    ''|*[!0-9]*) echo "HOLD: benchmark zstd levels must be positive integers" >&2; exit 2 ;;
  esac
  if [ "$level" -lt 1 ] || [ "$level" -gt 22 ]; then
    echo "HOLD: benchmark zstd levels must be from 1 through 22" >&2
    exit 2
  fi
  archive="$output/$artifact_name-zstd-$level.tar.zst"
  timing="$temporary_root/zstd-$level.time"
  /usr/bin/time -f '%e %U %S' -o "$timing" \
    sh -c 'tar --numeric-owner --xattrs --acls -C "$1" -cf - . | zstd -T0 "-$2" -o "$3"' \
    sh "$rootfs" "$level" "$archive"
  emit_result zstd "$level" "$archive" "$timing"
done
