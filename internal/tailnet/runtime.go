package tailnet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Runner interface {
	Run(context.Context, string) (controllerhost.Result, error)
}
type StdinRunner interface {
	Runner
	RunWithStdin(context.Context, string, io.Reader) (controllerhost.Result, error)
}
type GuestFacts struct {
	Exists, Running bool
	Config          map[string]string
}

const inventoryCommand = "pvesh get /cluster/resources --type vm --output-format json"
const TemplatePath = "/var/lib/boetticher/tailnet-image/rootfs.tar.zst"
const PackagePath = "/var/lib/boetticher/tailnet-image/tailscale.deb"

func InspectGuest(ctx context.Context, r Runner) (GuestFacts, error) {
	result, err := r.Run(ctx, inventoryCommand)
	if err != nil {
		return GuestFacts{}, fmt.Errorf("inspect Host guest inventory: %w", err)
	}
	var guests []struct {
		VMID         int
		Type, Status string
	}
	if json.Unmarshal(result.Stdout, &guests) != nil || strings.TrimSpace(string(result.Stdout)) == "null" {
		return GuestFacts{}, errors.New("malformed Host guest inventory")
	}
	found, running := false, false
	for _, g := range guests {
		if g.VMID == GuestVMID {
			if found || g.Type != "lxc" {
				return GuestFacts{}, errors.New("VMID 200 conflicts with Tailnet LXC")
			}
			found = true
			running = g.Status == "running"
		}
	}
	if !found {
		return GuestFacts{}, nil
	}
	result, err = r.Run(ctx, "pct config 200")
	if err != nil {
		return GuestFacts{}, fmt.Errorf("read Tailnet LXC configuration: %w", err)
	}
	c := map[string]string{}
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			return GuestFacts{}, errors.New("malformed LXC configuration")
		}
		if _, exists := c[k]; exists {
			return GuestFacts{}, errors.New("duplicate LXC configuration key")
		}
		c[k] = strings.TrimSpace(v)
	}
	if err := ValidateGuestConfig(c); err != nil {
		return GuestFacts{}, err
	}
	return GuestFacts{Exists: true, Running: running, Config: c}, nil
}
func options(s string) (map[string]string, error) {
	m := map[string]string{}
	for _, t := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(t, "=")
		if !ok {
			return nil, errors.New("malformed LXC option")
		}
		if _, ok = m[k]; ok {
			return nil, errors.New("duplicate LXC option")
		}
		m[k] = v
	}
	return m, nil
}
func ValidateGuestConfig(c map[string]string) error {
	bad := func() error {
		return errors.New("VMID 200 is not the exact owned unprivileged Tailnet LXC; refusing mutation")
	}
	tags := map[string]bool{}
	for _, t := range strings.Split(c["tags"], ";") {
		tags[t] = true
	}
	if c["hostname"] != GuestName || !tags[OwnerTag] || !tags["boetticher"] || !tags["managed"] || c["unprivileged"] != "1" {
		return bad()
	}
	if !regexp.MustCompile(`^boetticher-data:(subvol|vm)-200-disk-[0-9]+$`).MatchString(strings.Split(c["rootfs"], ",")[0]) {
		return bad()
	}
	for k, v := range c {
		if (strings.HasPrefix(k, "net") && k != "net0") || (strings.HasPrefix(k, "dev") && k != "dev0") || strings.HasPrefix(k, "mp") || strings.HasPrefix(k, "lxc.") || k == "hookscript" || (k == "features" && v != "") {
			return bad()
		}
	}
	n, err := options(c["net0"])
	if err != nil {
		return bad()
	}
	for k, v := range map[string]string{"name": "eth0", "bridge": "vmbr1", "tag": "5", "ip": "dhcp", "ip6": "manual", "firewall": "1"} {
		if n[k] != v {
			return bad()
		}
	}
	if !strings.EqualFold(n["hwaddr"], GuestMAC) {
		return bad()
	}
	for k, v := range n {
		switch k {
		case "name", "bridge", "tag", "ip", "ip6", "firewall", "hwaddr":
		case "type":
			if v != "veth" {
				return bad()
			}
		case "mtu":
			if v != "1500" {
				return bad()
			}
		default:
			return bad()
		}
	}
	d, err := options(c["dev0"])
	if err != nil || d["path"] != "/dev/net/tun" || d["mode"] != "0666" {
		return bad()
	}
	for k, v := range d {
		if k != "path" && k != "mode" && !(k == "uid" && v == "0") && !(k == "gid" && v == "0") {
			return bad()
		}
	}
	if c["nameserver"] != Resolver || c["onboot"] != "1" {
		return bad()
	}
	return nil
}
func shellQuote(s string) string        { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func GuestCommand(script string) string { return "pct exec 200 -- /bin/sh -c " + shellQuote(script) }

const tailnetAuthScript = `set -eu
umask 077
key=$(mktemp /run/boetticher-tailnet-auth.XXXXXX)
trap 'rm -f -- "$key"' EXIT HUP INT TERM
cat >"$key"
tailscale up --timeout=45s --auth-key=file:"$key"` + preferenceArgs + ` >/dev/null 2>&1`

func RuntimeReady(ctx context.Context, r Runner) bool {
	ready, _ := RuntimeReadyState(ctx, r)
	return ready
}

// RuntimeReadyState distinguishes a failed guest readiness probe from a
// failed Host transport. An owned guest may need runtime repair before native
// Tailnet status can be read, but transport failures must remain fatal.
func RuntimeReadyState(ctx context.Context, r Runner) (bool, error) {
	files := RuntimeFiles()
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("set -eu\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "test ! -L %s\ntest \"$(sha256sum %s | cut -d ' ' -f 1)\" = %s\n", shellQuote(k), shellQuote(k), shellQuote(fmt.Sprintf("%x", sha256.Sum256([]byte(files[k])))))
	}
	b.WriteString("test \"$(sysctl -n net.ipv4.ip_forward)\" = 1\nsystemctl is-active --quiet tailscaled\nsystemctl is-enabled --quiet tailscaled\nsystemctl is-active --quiet boetticher-tailnet-policy\n")
	b.WriteString("test -s /run/boetticher-tailnet-policy.sha256\ntest \"$(nft --stateless list table inet boetticher_tailnet | sha256sum | cut -d ' ' -f 1)\" = \"$(cat /run/boetticher-tailnet-policy.sha256)\"\n")
	fmt.Fprintf(&b, "test \"$(dpkg-query -W -f='${Version}' tailscale)\" = %s\n", shellQuote(Version))
	result, err := r.Run(ctx, GuestCommand(b.String()))
	if err == nil {
		return true, nil
	}
	if result.ExitCode == 1 {
		return false, nil
	}
	return false, fmt.Errorf("inspect Tailnet runtime: %w", err)
}
func ReadStatus(ctx context.Context, r Runner) (Report, error) {
	// Status crosses the Proxmox SSH transport several times (inventory,
	// config, native status/preferences, and the runtime proof). Allow the
	// caller's bounded daemon budget to absorb normal LAN/coordination jitter
	// instead of turning a slow but healthy router into a hard failure.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	g, err := InspectGuest(ctx, r)
	if err != nil {
		return NewReport(true, Failed, err.Error()), err
	}
	if !g.Exists {
		return NewReport(true, Failed, "Configured Tailnet guest is absent; run module tailnet apply"), nil
	}
	if !g.Running {
		return NewReport(true, Failed, "Tailnet guest is stopped; run module tailnet apply"), nil
	}
	status, err := r.Run(ctx, GuestCommand("tailscale status --json --peers=false"))
	if err != nil {
		return NewReport(true, Failed, "Tailscale native status unavailable"), err
	}
	prefs, err := r.Run(ctx, GuestCommand("tailscale debug prefs"))
	if err != nil {
		return NewReport(true, Failed, "Tailscale native preferences unavailable"), err
	}
	report, err := ParseNative(status.Stdout, prefs.Stdout)
	if err != nil {
		return report, err
	}
	if report.State == Healthy && !RuntimeReady(ctx, r) {
		return NewReport(true, Failed, "Tailnet persistent or loaded runtime differs from intent"), nil
	}
	return report, nil
}
func CreateGuest(ctx context.Context, r Runner) error {
	g, err := InspectGuest(ctx, r)
	if err != nil {
		return err
	}
	if g.Exists {
		return nil
	}
	cmd := "pct create 200 " + TemplatePath + " --hostname " + GuestName + " --unprivileged 1 --ostype debian --rootfs boetticher-data:4 --memory 512 --swap 0 --cores 1 --onboot 1 --startup order=20 --net0 " + shellQuote("name=eth0,bridge=vmbr1,tag=5,ip=dhcp,ip6=manual,hwaddr="+GuestMAC+",firewall=1") + " --dev0 path=/dev/net/tun,mode=0666 --nameserver " + Resolver + " --tags " + shellQuote("boetticher;managed;module;"+OwnerTag)
	if _, err = r.Run(ctx, cmd); err != nil {
		return fmt.Errorf("create Tailnet LXC: %w", err)
	}
	_, err = InspectGuest(ctx, r)
	return err
}
func InstallRuntime(ctx context.Context, r StdinRunner) error {
	g, err := InspectGuest(ctx, r)
	if err != nil {
		return err
	}
	if !g.Exists {
		return errors.New("Tailnet guest is absent")
	}
	if !g.Running {
		if _, err = r.Run(ctx, "pct start 200"); err != nil {
			return fmt.Errorf("start Tailnet LXC: %w", err)
		}
	}
	if RuntimeReady(ctx, r) {
		return nil
	}
	got, err := r.Run(ctx, GuestCommand("dpkg-query -W -f='${Version}' tailscale"))
	if err != nil || strings.TrimSpace(string(got.Stdout)) != Version {
		got, err = r.Run(ctx, "sha256sum "+PackagePath)
		if err != nil || !strings.HasPrefix(string(got.Stdout), PackageSHA256+" ") {
			return errors.New("pinned Tailnet package unavailable or checksum mismatch")
		}
		if _, err = r.Run(ctx, "pct push 200 "+PackagePath+" /run/boetticher-tailscale.deb --perms 0600"); err != nil {
			return err
		}
		if _, err = r.Run(ctx, GuestCommand("set -eu; trap 'rm -f /run/boetticher-tailscale.deb' EXIT; dpkg -i /run/boetticher-tailscale.deb")); err != nil {
			return errors.New("install pinned Tailscale package failed")
		}
	}
	if _, err = r.Run(ctx, GuestCommand("sysctl -q -w net.ipv4.ip_forward=0")); err != nil {
		return err
	}
	files := RuntimeFiles()
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		mode := "0644"
		if strings.HasPrefix(k, "/usr/local/libexec/") {
			mode = "0755"
		}
		parent := k[:strings.LastIndex(k, "/")]
		script := "set -eu; test ! -L " + shellQuote(parent) + "; install -d -m 0755 " + shellQuote(parent) + "; test ! -L " + shellQuote(k) + "; tmp=$(mktemp " + shellQuote(parent+"/.tailnet.XXXXXX") + "); trap 'rm -f \"$tmp\"' EXIT; cat > \"$tmp\"; chmod " + mode + " \"$tmp\"; mv -f \"$tmp\" " + shellQuote(k)
		if _, err = r.RunWithStdin(ctx, GuestCommand(script), strings.NewReader(files[k])); err != nil {
			return fmt.Errorf("install Tailnet runtime asset %s: %w", k, err)
		}
	}
	_, err = r.Run(ctx, GuestCommand("set -eu; systemctl daemon-reload; systemctl unmask tailscaled; systemctl enable boetticher-tailnet-policy tailscaled; systemctl restart boetticher-tailnet-policy; systemctl start tailscaled"))
	return err
}

const preferenceArgs = " --accept-dns=false --accept-routes=false --advertise-routes=10.10.0.0/16 --snat-subnet-routes=true --advertise-exit-node=false --exit-node= --ssh=false"

func Configure(ctx context.Context, r StdinRunner, key []byte) error {
	g, err := InspectGuest(ctx, r)
	if err != nil {
		return err
	}
	if !g.Exists {
		return errors.New("Tailnet guest is absent")
	}
	if len(key) > 0 {
		if _, err := r.RunWithStdin(ctx, GuestCommand(tailnetAuthScript), bytes.NewReader(key)); err != nil {
			return errors.New("Tailnet enrollment failed; intent retained, retry apply with an auth key")
		}
		return nil
	}
	status, statusErr := r.Run(ctx, GuestCommand("tailscale status --json --peers=false"))
	command := "systemctl start tailscaled; tailscale set" + preferenceArgs
	var native struct {
		BackendState string
		Self         *struct {
			Online *bool
		}
	}
	reconnect := false
	if statusErr == nil && json.Unmarshal(status.Stdout, &native) == nil {
		reconnect = native.BackendState == "Stopped"
		if native.Self != nil && native.Self.Online != nil && !*native.Self.Online {
			reconnect = true
		}
	}
	if reconnect {
		// tailscale up without an auth key reuses the persisted node identity.
		// It brings a deliberately stopped backend back without re-enrollment.
		command = "systemctl start tailscaled; tailscale up --timeout=45s" + preferenceArgs
	}
	if _, err := r.Run(ctx, GuestCommand(command)); err != nil {
		return errors.New("Tailnet preference reconciliation failed; enrollment may be required")
	}
	return nil
}
func Teardown(ctx context.Context, r Runner) error {
	g, err := InspectGuest(ctx, r)
	if err != nil {
		return err
	}
	if !g.Exists {
		return nil
	}
	if g.Running {
		if _, err = r.Run(ctx, "pct stop 200"); err != nil {
			return fmt.Errorf("stop owned Tailnet guest: %w", err)
		}
	}
	if _, err = InspectGuest(ctx, r); err != nil {
		return err
	}
	if _, err = r.Run(ctx, "pct destroy 200"); err != nil {
		return fmt.Errorf("destroy owned Tailnet guest: %w", err)
	}
	g, err = InspectGuest(ctx, r)
	if err != nil {
		return err
	}
	if g.Exists {
		return errors.New("Tailnet guest remains after teardown")
	}
	return nil
}
