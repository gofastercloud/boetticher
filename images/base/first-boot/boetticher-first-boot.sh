#!/bin/sh
set -eu

key=/run/boetticher/bootstrap/operator.pub
bootstrap_key="$key"
if [ ! -s "$bootstrap_key" ] && [ -s /root/.ssh/authorized_keys ]; then
  bootstrap_key=/root/.ssh/authorized_keys
fi

identity_dir=/var/lib/boetticher/identity/ssh
install -d -m 0700 -o root -g root "$identity_dir"
if [ ! -s "$identity_dir/ssh_host_ed25519_key" ]; then
  ssh-keygen -q -t ed25519 -N '' -f "$identity_dir/ssh_host_ed25519_key"
  chmod 0600 "$identity_dir/ssh_host_ed25519_key"
  chmod 0644 "$identity_dir/ssh_host_ed25519_key.pub"
fi

if [ ! -s "$bootstrap_key" ]; then
	systemctl disable boetticher-first-boot.service
	exit 0
fi

install -d -m 0700 -o labadmin -g labadmin /home/labadmin/.ssh
install -m 0600 -o labadmin -g labadmin "$bootstrap_key" /home/labadmin/.ssh/authorized_keys
rm -f /root/.ssh/authorized_keys
rm -f "$key"
systemctl disable boetticher-first-boot.service
