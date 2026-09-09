#!/bin/sh
set -eu

usage() {
  cat <<'EOF'
Usage: cleanup-controller-storage.sh [--root PATH] [--cache-root PATH]
       [--keep-releases COUNT] [--max-age-days DAYS] [--yes]

The default is a read-only report. Deletion requires --yes.
EOF
}

die() { printf 'Controller cleanup: FAIL — %s\n' "$1" >&2; exit 1; }
root=${BOETTICHER_INSTALL_ROOT:-/opt/boetticher}
cache_root=${BOETTICHER_CONTROLLER_CACHE_ROOT:-${TMPDIR:-/tmp}/boetticher-controller-cache}
keep=2
age=30
yes=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --root) [ "$#" -ge 2 ] || die '--root requires a path'; root=$2; shift 2 ;;
    --cache-root) [ "$#" -ge 2 ] || die '--cache-root requires a path'; cache_root=$2; shift 2 ;;
    --keep-releases) [ "$#" -ge 2 ] || die '--keep-releases requires a count'; keep=$2; shift 2 ;;
    --max-age-days) [ "$#" -ge 2 ] || die '--max-age-days requires a count'; age=$2; shift 2 ;;
    --yes) yes=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option $1" ;;
  esac
done
case "$keep:$age" in *[!0-9:]*|:*) die 'keep and age must be non-negative integers' ;; esac
[ -d "$root/releases" ] || { printf '%s\n' 'No controller release directory; nothing to do.'; exit 0; }
[ -d "$root" ] || die 'install root is not a directory'
case "$root" in /*) ;; *) root=$(CDPATH='' cd -- "$root" && pwd) ;; esac
current=$(readlink "$root/current" 2>/dev/null || true)
rollback=$(readlink "$root/rollback" 2>/dev/null || true)
normalize_link() {
  link_name=$1
  link_target=$2
  [ -n "$link_target" ] || die "$link_name symlink is missing or unreadable"
  case "$link_target" in
    "$root"/releases/*) relative=${link_target#"$root/"} ;;
    releases/*) relative=$link_target ;;
    *) die "$link_name symlink points outside the release directory" ;;
  esac
  [ -d "$root/$relative" ] || die "$link_name symlink target is missing"
  printf '%s\n' "$relative"
}
current=$(normalize_link current "$current")
if [ -L "$root/rollback" ]; then
  rollback=$(normalize_link rollback "$rollback")
else
  rollback=''
fi
cutoff=$(date -v-"${age}"d +%s 2>/dev/null || date -d "${age} days ago" +%s)
index=0
find "$root/releases" -mindepth 1 -maxdepth 1 -type d -name '[A-Za-z0-9._-]*' -exec sh -c 'for path do stat -f "%m %N" "$path" 2>/dev/null || stat -c "%Y %n" "$path"; done' sh {} + | sort -nr | while IFS=' ' read -r mtime release; do
  [ "$(stat -f '%Su' "$release" 2>/dev/null || stat -c '%U' "$release")" = root ] || continue
  target=${release#"$root/"}
  [ "$target" = "$current" ] && continue
  [ "$target" = "$rollback" ] && continue
  index=$((index + 1))
  if [ "$index" -gt "$keep" ] && [ "$mtime" -lt "$cutoff" ]; then
    if [ "$yes" -eq 1 ]; then rm -rf -- "$release"; printf 'Removed stale release: %s\n' "$release"; else printf 'Would remove stale release: %s\n' "$release"; fi
  fi
done
if [ -d "$cache_root" ]; then
  find "$cache_root" -mindepth 1 -maxdepth 1 -type f -name 'boetticher-controller-*' -mtime "+$age" -print
fi
