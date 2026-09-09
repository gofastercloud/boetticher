#!/usr/bin/env python3
"""Own and safely reclaim short lived build directories.

The marker and fcntl lock are deliberately boring.  A cleanup operation may
remove a directory only when it is marked by this tool, old enough, and its
lock can be acquired without following symlinks.
"""
import fcntl
import json
import os
import shutil
import secrets
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

MARKER = ".boetticher-build-owned"
LOCK = ".boetticher-build.lock"
VERSION = 1
PREFIXES = ("run-", "boetticher-openwrt-build.", "boetticher-tailnet-builder.")


def root_path(value):
    root = Path(value).expanduser()
    if root.is_symlink() or not root.is_absolute():
        raise SystemExit("HOLD: build temporary root must be an absolute non-symlink path")
    current = Path(root.anchor)
    for part in root.parts[1:]:
        current /= part
        if current == Path("/var"):
            continue  # macOS /var is the trusted /private/var compatibility alias.
        if current.exists() and current.is_symlink():
            raise SystemExit("HOLD: build temporary root has a symlinked ancestor")
    root = Path(os.path.realpath(root))
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink():
        raise SystemExit("HOLD: build temporary root became a symlink")
    return root


def run(root, argv, keep):
    if not argv:
        raise SystemExit("HOLD: build-temp run requires a command")
    root = root_path(root)
    path = Path(tempfile.mkdtemp(prefix="run-", dir=root))
    marker = path / MARKER
    lock_path = path / LOCK
    lock_path.touch(mode=0o600)
    token = secrets.token_hex(16)
    marker.write_text(json.dumps({"version": VERSION, "pid": os.getpid(), "created": time.time(), "token": token}) + "\n")
    marker.chmod(0o600)
    lock = lock_path.open("r+")
    fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
    os.set_inheritable(lock.fileno(), True)
    env = os.environ.copy()
    token_path = path / ".boetticher-build-token"
    token_path.write_text(token + "\n")
    token_path.chmod(0o600)
    env.update({"BOETTICHER_BUILD_TEMP_ACTIVE": "1", "BOETTICHER_BUILD_TEMP_DIR": str(path), "BOETTICHER_BUILD_TEMP_LOCK": str(lock_path), "BOETTICHER_BUILD_TEMP_TOKEN": token})
    try:
        child = subprocess.Popen(argv, env=env, close_fds=False)
    except OSError:
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        lock.close()
        shutil.rmtree(path)
        raise

    def forward(signum, _frame):
        try:
            child.send_signal(signum)
        except ProcessLookupError:
            pass

    signal.signal(signal.SIGTERM, forward)
    signal.signal(signal.SIGINT, forward)
    try:
        status = child.wait()
        if keep:
            (path / ".boetticher-build-kept").write_text("kept by operator\n")
    finally:
        if not keep and path.exists():
            shutil.rmtree(path)
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        lock.close()
    if keep:
        print(f"kept build files: {path}", file=sys.stderr)
    return status


def inspect(root, grace, remove=False, keep=False):
    root = root_path(root)
    now = time.time()
    for path in sorted(root.iterdir()):
        if not path.name.startswith(PREFIXES) or (path / ".boetticher-build-kept").exists():
            continue
        reason = None
        if path.is_symlink() or not path.is_dir():
            reason = "refuse: symlink or non-directory"
        elif ((path / MARKER).is_symlink() or not (path / MARKER).is_file()
              or (path / LOCK).is_symlink() or not (path / LOCK).is_file()):
            reason = "skip: missing ownership marker or lock"
        elif now - path.stat().st_mtime < grace:
            reason = "skip: younger than grace period"
        else:
            try:
                marker_fd = os.open(path / MARKER, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                with os.fdopen(marker_fd) as marker_file:
                    marker = json.load(marker_file)
                if marker.get("version") != VERSION:
                    raise ValueError("unsupported marker")
            except (OSError, ValueError, json.JSONDecodeError):
                reason = "skip: invalid ownership marker"
            if reason is None:
                try:
                    lock_fd = os.open(path / LOCK, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
                    with os.fdopen(lock_fd, "r+") as lock:
                        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        if path.is_symlink() or not path.is_dir() or not (path / MARKER).is_file():
                            reason = "refuse: build directory changed during cleanup"
                            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
                            continue
                        # Keep the lock through unlinking so a surviving child
                        # holding an inherited descriptor cannot be reclaimed.
                        if remove and not keep:
                            print(f"remove: owned inactive build {path}")
                            shutil.rmtree(path)
                            reason = "removed"
                            continue
                        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
                except BlockingIOError:
                    reason = "skip: active build lock"
                except OSError:
                    reason = "skip: lock could not be proven inactive"
        if reason is None:
            reason = "remove: owned inactive build"
        print(f"{reason} {path}")


def main():
    raw = sys.argv[1:]
    if len(raw) < 2 or raw[0] not in ("run", "preview", "clean"):
        raise SystemExit("usage: build-temp.py run|preview|clean ROOT [--yes] [--keep-build-files] [--grace SECONDS] [-- COMMAND ...]")
    command, root = raw[:2]
    rest = raw[2:]
    child = []
    if "--" in rest:
        split = rest.index("--")
        options, child = rest[:split], rest[split + 1:]
    else:
        options = rest
    keep = "--keep-build-files" in options
    yes = "--yes" in options
    grace = 3600.0
    if "--grace" in options:
        index = options.index("--grace")
        try:
            grace = float(options[index + 1])
        except (IndexError, ValueError):
            raise SystemExit("HOLD: --grace requires seconds")
    if command == "run":
        raise SystemExit(run(root, child, keep))
    inspect(root, grace, remove=command == "clean" and yes, keep=keep)


if __name__ == "__main__":
    main()
