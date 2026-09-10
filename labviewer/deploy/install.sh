#!/bin/sh
set -eu

prefix=${PREFIX:-/usr/local}
binary=${1:?usage: install.sh /path/to/boetticher-labviewer}
test -x "$binary"

install -d -o root -g root -m 0755 "$prefix/libexec"
install -o root -g root -m 0755 "$binary" "$prefix/libexec/boetticher-labviewer"
install -d -o root -g root -m 0755 /etc/boetticher
install -d -o root -g root -m 0755 /etc/systemd/system
install -o root -g root -m 0644 "$(dirname "$0")/boetticher-labviewer.service" /etc/systemd/system/boetticher-labviewer.service
if ! getent group boetticher-labviewer >/dev/null 2>&1; then groupadd --system boetticher-labviewer; fi
if ! id boetticher-labviewer >/dev/null 2>&1; then useradd --system --gid boetticher-labviewer --home-dir /var/lib/boetticher-labviewer --create-home --shell /usr/sbin/nologin boetticher-labviewer; fi
install -d -o boetticher-labviewer -g boetticher-labviewer -m 0750 /var/lib/boetticher/homepage/config
chown root:boetticher-labviewer /etc/boetticher/lab.yml
chmod 0640 /etc/boetticher/lab.yml
systemctl daemon-reload
systemctl enable --now boetticher-labviewer.service
