package host

import (
	"errors"
	"fmt"
	"strings"
)

const (
	proxmoxRepositoryPath = "/etc/apt/sources.list.d/boetticher-pve-no-subscription.sources"
	headlessPolicyPath    = "/etc/systemd/logind.conf.d/90-boetticher-headless.conf"
)

const proxmoxRepository = "Types: deb\nURIs: http://download.proxmox.com/debian/pve\nSuites: trixie\nComponents: pve-no-subscription\n"

const headlessPolicy = "[Login]\nHandleLidSwitch=ignore\nHandleLidSwitchExternalPower=ignore\nHandleLidSwitchDocked=ignore\nHandleSuspendKey=ignore\nHandleHibernateKey=ignore\nIdleAction=ignore\n"

// HostBaselineTeardownCommand removes only files whose complete contents match
// the Controller's known templates. Shared packages and unknown repository or
// power configuration are deliberately preserved.
func HostBaselineTeardownCommand() string {
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
	return "set -eu; for path in " + proxmoxRepositoryPath + " " + headlessPolicyPath + "; do test ! -L \"$path\"; done; if [ -f " + proxmoxRepositoryPath + " ] && printf %s " + quote(proxmoxRepository) + " | cmp -s - " + proxmoxRepositoryPath + "; then rm -f " + proxmoxRepositoryPath + "; fi; if [ -f " + headlessPolicyPath + " ] && printf %s " + quote(headlessPolicy) + " | cmp -s - " + headlessPolicyPath + "; then rm -f " + headlessPolicyPath + "; systemctl daemon-reload; systemctl reload systemd-logind.service; fi"
}

// NetworkTeardownCommand removes an exact, owned vmbr1 and its host IPv6
// suppression while protecting vmbr0 and the management route.
func NetworkTeardownCommand(plan NetworkPlan) (string, error) {
	if plan.State != "exact" || !plan.Bridge.Owned || !plan.Bridge.IPv6Disabled || len(plan.Bridge.PhysicalMembers) != 0 || len(plan.Bridge.HostAddresses) != 0 || plan.Bridge.Gateway != "" {
		return "", fmt.Errorf("network state %s is not an exact owned vmbr1 teardown target: %s", plan.State, plan.Detail)
	}
	return `set -eu
file=/etc/network/interfaces
test ! -L "$file"; test -f "$file"
test -f /etc/sysctl.d/70-boetticher-vmbr1.conf; test ! -L /etc/sysctl.d/70-boetticher-vmbr1.conf
printf '%s\n' '# Keep the Proxmox host off the virtual LAB at L3.' 'net.ipv6.conf.vmbr1.disable_ipv6=1' | cmp -s - /etc/sysctl.d/70-boetticher-vmbr1.conf
test -f /etc/network/if-up.d/boetticher-vmbr1; test ! -L /etc/network/if-up.d/boetticher-vmbr1
printf '%s\n' '#!/bin/sh' '# Managed by Boetticher: vmbr1 host IPv6 suppression.' 'set -eu' '[ "${IFACE:-}" = vmbr1 ] || exit 0' 'sysctl -q -w net.ipv6.conf.vmbr1.disable_ipv6=1' | cmp -s - /etc/network/if-up.d/boetticher-vmbr1
test -z "$(bridge link | awk '$NF == "vmbr1" { print; exit }')"
test -z "$(ip -json address show dev vmbr1 | grep -F '"local"' || true)"
ip -d link show vmbr1 | grep -Eq 'vlan_filtering (1|on)'
if ifquery --state vmbr1 >/dev/null 2>&1; then ifdown vmbr1; fi
if ip link show vmbr1 >/dev/null 2>&1; then ip link delete vmbr1 type bridge; fi
test ! -e /sys/class/net/vmbr1
tmp=$(mktemp /etc/network/interfaces.boetticher.XXXXXX)
trap 'rm -f "$tmp"' EXIT
awk '
  /^auto vmbr1$/ { skip=1; next }
  skip && /^iface vmbr1 / { next }
  skip && /^(auto|iface|allow-|source)/ { skip=0 }
  !skip { print }
' "$file" >"$tmp"
chmod 644 "$tmp"; mv -f "$tmp" "$file"
rm -f /etc/sysctl.d/70-boetticher-vmbr1.conf /etc/network/if-up.d/boetticher-vmbr1
if [ -e /root/boetticher-network-pre-change.interfaces ]; then test ! -L /root/boetticher-network-pre-change.interfaces; rm -f /root/boetticher-network-pre-change.interfaces; fi
`, nil
}

func validateTeardownConfig(config LabConfig) error {
	if config.Proxmox.Node == "" {
		return errors.New("host enrollment is already absent")
	}
	if config.Storage == nil || config.Storage.Device == "" {
		return errors.New("dedicated storage selection is absent")
	}
	if config.Network == nil || config.Network.InternalBridge != InternalBridge {
		return errors.New("internal network selection is absent")
	}
	return nil
}
