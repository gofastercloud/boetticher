#!/bin/sh
set -eu

usage() {
  cat <<'EOF'
Usage: cleanup-local-storage.sh [--root PATH] [--keep COUNT]
       [--max-age-days DAYS] [--yes]

The default is a read-only report. Deletion requires --yes.
Only clearly named stale directories directly below PATH are eligible.
EOF
}

die() { printf 'Local cleanup: FAIL — %s\n' "$1" >&2; exit 1; }
root=${BOETTICHER_LOCAL_STORAGE_ROOT:-generated}
keep=${BOETTICHER_LOCAL_STORAGE_KEEP:-2}
age=${BOETTICHER_LOCAL_STORAGE_MAX_AGE_DAYS:-30}
yes=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --root) [ "$#" -ge 2 ] || die '--root requires a path'; root=$2; shift 2 ;;
    --keep) [ "$#" -ge 2 ] || die '--keep requires a count'; keep=$2; shift 2 ;;
    --max-age-days) [ "$#" -ge 2 ] || die '--max-age-days requires a count'; age=$2; shift 2 ;;
    --yes) yes=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option $1" ;;
  esac
done
case "$keep:$age" in *[!0-9:]*|:*) die 'keep and age must be non-negative integers' ;; esac
[ -d "$root" ] || { printf 'Local storage root does not exist: %s\n' "$root"; exit 0; }
[ ! -L "$root" ] || die 'storage root must not be a symlink'
case "$root" in /*) ;; *) root=$(CDPATH='' cd -- "$root" && pwd) ;; esac
cutoff=$(date -v-"${age}"d +%s 2>/dev/null || date -d "${age} days ago" +%s)
count=0
find "$root" -mindepth 1 -maxdepth 1 \( -name 'artifacts-stale-*' -o -name 'boetticher-build-*' -o -name 'boetticher-download-*' \) -type d -print | sort | while IFS= read -r path; do
  [ -L "$path" ] && { printf 'Refused symlink: %s\n' "$path"; continue; }
  owner=$(stat -f '%Su' "$path" 2>/dev/null || stat -c '%U' "$path")
  [ "$owner" = "$(id -un)" ] || { printf 'Refused non-owned path: %s\n' "$path"; continue; }
  mtime=$(stat -f '%m' "$path" 2>/dev/null || stat -c '%Y' "$path")
  count=$((count + 1))
  if [ "$count" -gt "$keep" ] && [ "$mtime" -lt "$cutoff" ]; then
    if [ "$yes" -eq 1 ]; then rm -rf -- "$path"; printf 'Removed stale local tree: %s\n' "$path"; else printf 'Would remove stale local tree: %s\n' "$path"; fi
  else
    printf 'Kept local tree: %s\n' "$path"
  fi
done
