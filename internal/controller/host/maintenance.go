package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Runner is the one remote-command operation Host maintenance needs. The
// strict Controller-to-Host Transport satisfies it; tests use fakes.
type Runner interface {
	Run(ctx context.Context, command string) (Result, error)
}

// ReadNodes and ReadGuests are the read-only Proxmox inventory used by Host
// maintenance. Unlike the observational inventory, an undecodable guest
// listing is an error: unknown is never treated as empty.
func ReadNodes(ctx context.Context, runner Runner) ([]Node, error) {
	output, err := runner.Run(ctx, cmdNodes)
	if err != nil {
		return nil, fmt.Errorf("read Proxmox nodes: %w", err)
	}
	return parseNodes(output.Stdout)
}

func ReadGuests(ctx context.Context, runner Runner) ([]Guest, error) {
	output, err := runner.Run(ctx, cmdGuests)
	if err != nil {
		return nil, fmt.Errorf("read Proxmox guests: %w", err)
	}
	var list []json.RawMessage
	if json.Unmarshal(output.Stdout, &list) != nil || list == nil {
		var envelope struct {
			Data []json.RawMessage `json:"data"`
		}
		if json.Unmarshal(output.Stdout, &envelope) != nil || envelope.Data == nil {
			return nil, errors.New("decode Proxmox guest listing")
		}
	}
	return parseGuests(output.Stdout), nil
}

// AptRepositoryCommand prints every APT source file without changing it, plus
// the native subscription status. Parsing happens on the Controller.
const AptRepositoryCommand = `set -u; for path in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do [ -f "$path" ] || continue; printf 'BOETTICHER_SOURCE_FILE=%s\n' "$path"; cat "$path"; printf '\n'; done; status=$(pvesubscription get 2>/dev/null | awk -F': *' '$1 == "status" { print $2; exit }' || true); printf 'BOETTICHER_SUBSCRIPTION=%s\n' "$status"`

type AptSource struct {
	File       string
	URIs       []string
	Suites     []string
	Components []string
	Enabled    bool
}

type RepositoryState struct {
	Sources      []AptSource
	Subscription string
}

func ParseAptRepositories(output []byte) RepositoryState {
	var state RepositoryState
	var file string
	var block []string
	flush := func() {
		if file == "" {
			block = nil
			return
		}
		if strings.HasSuffix(file, ".sources") {
			state.Sources = append(state.Sources, parseDeb822Sources(file, block)...)
		} else {
			state.Sources = append(state.Sources, parseOneLineSources(file, block)...)
		}
		block = nil
	}
	for _, line := range strings.Split(string(output), "\n") {
		switch {
		case strings.HasPrefix(line, "BOETTICHER_SOURCE_FILE="):
			flush()
			file = strings.TrimPrefix(line, "BOETTICHER_SOURCE_FILE=")
		case strings.HasPrefix(line, "BOETTICHER_SUBSCRIPTION="):
			flush()
			file = ""
			state.Subscription = strings.TrimSpace(strings.TrimPrefix(line, "BOETTICHER_SUBSCRIPTION="))
		default:
			block = append(block, line)
		}
	}
	flush()
	return state
}

func parseOneLineSources(file string, lines []string) []AptSource {
	var sources []AptSource
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if index := strings.IndexByte(line, '#'); index >= 0 {
			line = strings.TrimSpace(line[:index])
		}
		fields := strings.Fields(line)
		if len(fields) < 3 || (fields[0] != "deb" && fields[0] != "deb-src") {
			continue
		}
		rest := fields[1:]
		if strings.HasPrefix(rest[0], "[") {
			for len(rest) > 0 && !strings.HasSuffix(rest[0], "]") {
				rest = rest[1:]
			}
			if len(rest) > 0 {
				rest = rest[1:]
			}
		}
		if len(rest) < 2 {
			continue
		}
		sources = append(sources, AptSource{File: file, URIs: []string{rest[0]}, Suites: []string{rest[1]}, Components: rest[2:], Enabled: true})
	}
	return sources
}

func parseDeb822Sources(file string, lines []string) []AptSource {
	var sources []AptSource
	fields := map[string]string{}
	last := ""
	emit := func() {
		if len(fields) == 0 {
			return
		}
		if uris := strings.Fields(fields["uris"]); len(uris) > 0 {
			enabled := true
			switch strings.ToLower(strings.TrimSpace(fields["enabled"])) {
			case "no", "false", "0":
				enabled = false
			}
			sources = append(sources, AptSource{File: file, URIs: uris, Suites: strings.Fields(fields["suites"]), Components: strings.Fields(fields["components"]), Enabled: enabled})
		}
		fields = map[string]string{}
		last = ""
	}
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			emit()
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if last != "" && last != "signed-by" {
				fields[last] += " " + strings.TrimSpace(line)
			}
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		last = strings.ToLower(strings.TrimSpace(key))
		fields[last] = strings.TrimSpace(value)
	}
	emit()
	return sources
}

func (s AptSource) uriContains(text string) bool {
	for _, uri := range s.URIs {
		if strings.Contains(uri, text) {
			return true
		}
	}
	return false
}

func (s AptSource) Describe() string {
	return strings.TrimSpace(fmt.Sprintf("%s %s %s (%s)", strings.Join(s.URIs, ","), strings.Join(s.Suites, ","), strings.Join(s.Components, " "), s.File))
}

// CheckRepositoryPolicy is the read-only upgrade preflight. It never rewrites
// sources: an enabled enterprise repository without an active subscription is
// a refusal with operator guidance.
func CheckRepositoryPolicy(state RepositoryState) ([]AptSource, error) {
	subscribed := strings.EqualFold(state.Subscription, "active")
	var enterprise []string
	var pve []AptSource
	for _, source := range state.Sources {
		if !source.Enabled {
			continue
		}
		if source.uriContains("enterprise.proxmox.com") {
			if !subscribed {
				enterprise = append(enterprise, source.Describe())
				continue
			}
		}
		if source.uriContains("download.proxmox.com/debian/pve") || source.uriContains("enterprise.proxmox.com/debian/pve") {
			pve = append(pve, source)
		}
	}
	if len(enterprise) > 0 {
		status := state.Subscription
		if status == "" {
			status = "unknown"
		}
		return nil, fmt.Errorf("Proxmox enterprise repository is enabled without an active subscription (status %s): %s; no packages were changed. Disable it on the Host (Proxmox web UI: Node > Updates > Repositories) or activate a subscription, then rerun the plan. Boetticher does not rewrite repositories during an upgrade", status, strings.Join(enterprise, "; "))
	}
	if len(pve) == 0 {
		return nil, errors.New("no enabled Proxmox VE package repository was found; run `boetticher host apply` to establish the no-subscription repository policy; no packages were changed")
	}
	return pve, nil
}

// Package update commands. The refresh is the only change a plan makes; the
// simulation and snapshots are read-only.
const (
	AptRefreshCommand  = "LC_ALL=C DEBIAN_FRONTEND=noninteractive apt-get -q -o DPkg::Lock::Timeout=300 update 2>&1"
	AptSimulateCommand = "LC_ALL=C apt-get -s -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold full-upgrade 2>&1"
	PackageSnapshotCmd = "dpkg-query -W -f='${db:Status-Abbrev}\\t${Package}\\t${Version}\\n'"
	RebootStateCommand = "printf 'BOETTICHER_RUNNING_KERNEL=%s\\n' \"$(uname -r)\"; printf 'BOETTICHER_NEWEST_KERNEL=%s\\n' \"$(ls -1 /boot/vmlinuz-* 2>/dev/null | sed 's#^/boot/vmlinuz-##' | sort -V | tail -n 1)\"; if test -e /var/run/reboot-required; then echo BOETTICHER_REBOOT_REQUIRED=1; else echo BOETTICHER_REBOOT_REQUIRED=0; fi"
	UpgradeUnit        = "boetticher-host-upgrade"
	UpgradeLog         = "/var/log/boetticher-host-upgrade.log"
	// The full-upgrade runs in a transient systemd unit so that an SSH drop
	// (for example while networking packages restart) cannot interrupt dpkg.
	AptUpgradeCommand = "systemd-run --quiet --unit=" + UpgradeUnit + " --wait --collect --service-type=exec --property=StandardOutput=truncate:" + UpgradeLog + " --property=StandardError=inherit --setenv=DEBIAN_FRONTEND=noninteractive --setenv=APT_LISTCHANGES_FRONTEND=none --setenv=LC_ALL=C /usr/bin/apt-get -y -q -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold full-upgrade"
	UpgradeLogTailCmd = "tail -n 40 " + UpgradeLog + " 2>/dev/null || true"
)

// RefreshProblems returns apt update lines that make the refreshed indexes
// untrustworthy for planning.
func RefreshProblems(output []byte) []string {
	var problems []string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "E:") || strings.Contains(line, "Failed to fetch") || strings.Contains(line, "Some index files failed to download") {
			problems = append(problems, line)
		}
	}
	return problems
}

type PackageChange struct {
	Name, From, To string
}

type UpgradePlan struct {
	Upgrades, Installs, Removals []PackageChange
}

func (p UpgradePlan) Count() int { return len(p.Upgrades) + len(p.Installs) + len(p.Removals) }

var simulatedLine = regexp.MustCompile(`^(Inst|Remv) (\S+)(?: \[([^\]]*)\])?(?: \((\S+))?`)

func ParseSimulatedUpgrade(output []byte) UpgradePlan {
	var plan UpgradePlan
	for _, line := range strings.Split(string(output), "\n") {
		match := simulatedLine.FindStringSubmatch(strings.TrimSpace(line))
		if match == nil {
			continue
		}
		change := PackageChange{Name: match[2], From: match[3], To: match[4]}
		switch {
		case match[1] == "Remv":
			plan.Removals = append(plan.Removals, change)
		case change.From != "":
			plan.Upgrades = append(plan.Upgrades, change)
		default:
			plan.Installs = append(plan.Installs, change)
		}
	}
	return plan
}

func IsKernelPackage(name string) bool {
	for _, prefix := range []string{"proxmox-kernel-", "pve-kernel-", "linux-image-"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func IsProxmoxPackage(name string) bool {
	for _, prefix := range []string{"pve-", "proxmox-", "libpve-", "libproxmox-"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	switch name {
	case "qemu-server", "lxc-pve", "lxcfs", "corosync", "spiceterm", "vncterm":
		return true
	}
	return false
}

// rebootPackages need a reboot to take effect even when they are not kernels.
var rebootPackages = map[string]bool{"intel-microcode": true, "amd64-microcode": true, "pve-firmware": true, "libc6": true, "systemd": true}

// RebootReasons is a prediction from the simulated change set; the
// authoritative answer comes from the Host after the upgrade.
func (p UpgradePlan) RebootReasons() []string {
	var reasons []string
	for _, change := range append(append([]PackageChange{}, p.Upgrades...), p.Installs...) {
		if IsKernelPackage(change.Name) || rebootPackages[change.Name] {
			reasons = append(reasons, change.Name)
		}
	}
	return reasons
}

// protectedPackages must never be removed by a full-upgrade; removal means the
// repository configuration is wrong.
var protectedPackages = map[string]bool{"proxmox-ve": true, "pve-manager": true, "pve-cluster": true, "qemu-server": true, "pve-container": true}

func (p UpgradePlan) ProtectedRemovals() []string {
	var names []string
	for _, change := range p.Removals {
		if protectedPackages[change.Name] {
			names = append(names, change.Name)
		}
	}
	return names
}

// ParsePackageSnapshot returns installed package versions from
// PackageSnapshotCmd.
func ParsePackageSnapshot(output []byte) map[string]string {
	packages := map[string]string{}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 3 || !strings.HasPrefix(strings.TrimSpace(fields[0]), "ii") && !strings.HasPrefix(strings.TrimSpace(fields[0]), "hi") {
			continue
		}
		packages[fields[1]] = fields[2]
	}
	return packages
}

// DiffPackages reports what actually changed between two snapshots.
func DiffPackages(before, after map[string]string) UpgradePlan {
	var diff UpgradePlan
	for name, version := range after {
		old, ok := before[name]
		switch {
		case !ok:
			diff.Installs = append(diff.Installs, PackageChange{Name: name, To: version})
		case old != version:
			diff.Upgrades = append(diff.Upgrades, PackageChange{Name: name, From: old, To: version})
		}
	}
	for name, version := range before {
		if _, ok := after[name]; !ok {
			diff.Removals = append(diff.Removals, PackageChange{Name: name, From: version})
		}
	}
	for _, list := range []*[]PackageChange{&diff.Upgrades, &diff.Installs, &diff.Removals} {
		sort.Slice(*list, func(i, j int) bool { return (*list)[i].Name < (*list)[j].Name })
	}
	return diff
}

type RebootState struct {
	RunningKernel, NewestKernel string
	Marker                      bool
}

func ParseRebootState(output []byte) (RebootState, error) {
	var state RebootState
	seen := 0
	for _, line := range strings.Split(string(output), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "BOETTICHER_RUNNING_KERNEL":
			state.RunningKernel, seen = value, seen+1
		case "BOETTICHER_NEWEST_KERNEL":
			state.NewestKernel, seen = value, seen+1
		case "BOETTICHER_REBOOT_REQUIRED":
			state.Marker, seen = value == "1", seen+1
		}
	}
	if seen != 3 || state.RunningKernel == "" {
		return RebootState{}, errors.New("Host reboot state is unavailable")
	}
	return state, nil
}

func (s RebootState) Required() bool {
	return s.Marker || (s.NewestKernel != "" && s.NewestKernel != s.RunningKernel)
}

func (s RebootState) Reason() string {
	var reasons []string
	if s.NewestKernel != "" && s.NewestKernel != s.RunningKernel {
		reasons = append(reasons, fmt.Sprintf("running kernel %s, newest installed %s", s.RunningKernel, s.NewestKernel))
	}
	if s.Marker {
		reasons = append(reasons, "/var/run/reboot-required is present")
	}
	if len(reasons) == 0 {
		return "running kernel " + s.RunningKernel + " is the newest installed"
	}
	return strings.Join(reasons, "; ")
}

// Guest reboot preflight.

const (
	BootIDCommand          = "cat /proc/sys/kernel/random/boot_id"
	GuestsServiceCommand   = "systemctl is-enabled pve-guests.service 2>/dev/null || true"
	GuestsServiceActiveCmd = "systemctl is-active pve-guests.service 2>/dev/null || true"
)

type GuestBootPolicy struct {
	Guest
	OnBoot   bool
	Order    int // 0 means unset: Proxmox starts these after ordered guests.
	Up, Down int // seconds; 0 means unset
}

// GuestConfigCommand reads one guest's native configuration.
func GuestConfigCommand(node string, guest Guest) (string, error) {
	if !safeIdentifier(node) || guest.VMID <= 0 || (guest.Type != "qemu" && guest.Type != "lxc") {
		return "", fmt.Errorf("unsafe guest identity %d (%s)", guest.VMID, guest.Type)
	}
	return fmt.Sprintf("pvesh get /nodes/%s/%s/%d/config --output-format json", node, guest.Type, guest.VMID), nil
}

func ParseGuestBootPolicy(guest Guest, output []byte) (GuestBootPolicy, error) {
	var config map[string]any
	if err := json.Unmarshal(output, &config); err != nil {
		return GuestBootPolicy{}, fmt.Errorf("decode guest %d configuration", guest.VMID)
	}
	policy := GuestBootPolicy{Guest: guest}
	switch value := config["onboot"].(type) {
	case float64:
		policy.OnBoot = value == 1
	case string:
		policy.OnBoot = value == "1"
	case bool:
		policy.OnBoot = value
	}
	startup, _ := config["startup"].(string)
	for _, part := range strings.Split(startup, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			key, value = "order", key
		}
		number, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || number < 0 {
			continue
		}
		switch key {
		case "order":
			policy.Order = number
		case "up":
			policy.Up = number
		case "down":
			policy.Down = number
		}
	}
	return policy, nil
}

// SortByStartOrder orders guests as Proxmox starts them: explicit orders
// ascending, then guests without an order, each tie broken by VMID.
func SortByStartOrder(policies []GuestBootPolicy) {
	sort.SliceStable(policies, func(i, j int) bool {
		left, right := policies[i], policies[j]
		if (left.Order == 0) != (right.Order == 0) {
			return left.Order != 0
		}
		if left.Order != right.Order {
			return left.Order < right.Order
		}
		return left.VMID < right.VMID
	})
}
