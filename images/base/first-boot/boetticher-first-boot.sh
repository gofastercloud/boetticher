#!/bin/sh
set -eu

key=/run/boetticher/bootstrap/operator.pub
bootstrap_key="$key"
if [ ! -s "$bootstrap_key" ] && [ -s /root/.ssh/authorized_keys ]; then
  bootstrap_key=/root/.ssh/authorized_keys
fi
if [ ! -s "$bootstrap_key" ]; then
  exit 0
fi

install -d -m 0700 -o labadmin -g labadmin /home/labadmin/.ssh
install -m 0600 -o labadmin -g labadmin "$bootstrap_key" /home/labadmin/.ssh/authorized_keys
rm -f /root/.ssh/authorized_keys
rm -f "$key"
systemctl disable boetticher-first-boot.service
systemctl stop boetticher-first-boot.service
