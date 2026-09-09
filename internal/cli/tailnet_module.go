package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/firewallmodule"
	"github.com/gofastercloud/boetticher/internal/pathguard"
	"github.com/gofastercloud/boetticher/internal/tailnet"
	"golang.org/x/term"
)

type tailnetOptions struct {
	yes, plan, json bool
	authKeyFile     string
}

func parseTailnetOptions(c string, a []string, approval bool) (tailnetOptions, error) {
	fs := flag.NewFlagSet(c, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var o tailnetOptions
	if approval {
		fs.BoolVar(&o.yes, "yes", false, "approve the change")
	}
	fs.BoolVar(&o.plan, "plan", false, "preview without changing state")
	fs.BoolVar(&o.json, "json", false, "emit JSON")
	if c == "module tailnet apply" {
		fs.StringVar(&o.authKeyFile, "auth-key-file", "", "operator-owned auth key file")
	}
	if e := fs.Parse(a); e != nil {
		return o, e
	}
	if fs.NArg() != 0 {
		return o, errors.New("unexpected positional arguments")
	}
	if o.plan && o.yes {
		return o, errors.New("--plan cannot be combined with --yes")
	}
	return o, nil
}
func runTailnetCapability(a string, args []string, in io.Reader, out, errOut io.Writer) error {
	switch a {
	case "plan":
		return runTailnetPlan(args, out)
	case "apply":
		return runTailnetApply(args, in, out, errOut)
	case "status":
		return runTailnetStatus(args, out)
	case "test":
		return runTailnetTest(args, out)
	case "teardown":
		return runTailnetTeardown(args, in, out)
	}
	return fmt.Errorf("module capability %q does not implement action %q", tailnet.Module, a)
}
func tailnetReservation() clientservices.Reservation {
	return clientservices.Reservation{Name: tailnet.GuestName, Zone: "TRANSIT", MAC: tailnet.GuestMAC, Address: tailnet.GuestAddress}
}

func missingTailnetDHCPSections(current, proposed controllerhost.LabConfig, state firewallmodule.ServiceState) map[string]struct{} {
	reservation := tailnetReservation()
	currentHas := false
	if current.Modules.DHCP != nil {
		for _, item := range current.Modules.DHCP.Reservations {
			if item == reservation {
				currentHas = true
				break
			}
		}
	}
	proposedHas := false
	if proposed.Modules.DHCP != nil {
		for _, item := range proposed.Modules.DHCP.Reservations {
			if item == reservation {
				proposedHas = true
				break
			}
		}
	}
	if currentHas || !proposedHas {
		return nil
	}
	for _, section := range state.DHCP {
		if section.Type == "host" && strings.EqualFold(section.Options["name"], tailnet.GuestName) {
			return map[string]struct{}{section.Name: {}}
		}
	}
	return nil
}
func runTailnetPlan(a []string, out io.Writer) error {
	o, e := parseTailnetOptions("module tailnet plan", a, false)
	_ = o
	if e != nil {
		return e
	}
	c, e := controllerhost.LoadConfig()
	if e != nil {
		return e
	}
	if _, e = prepareTailnet(c); e != nil {
		return e
	}
	on := c.Modules.Tailnet != nil && c.Modules.Tailnet.Enabled
	fmt.Fprintf(out, "Tailnet plan\n  Desired: %v\n  Guest: %s (VMID %d)\n", on, tailnet.GuestName, tailnet.GuestVMID)
	return nil
}
func prepareTailnet(c controllerhost.LabConfig) (controllerhost.LabConfig, error) {
	n := c
	n.Modules = n.Modules.Clone()
	if n.Modules.DNS == nil || !clientservices.Enabled(n.Modules.DNS.Enabled) || n.Modules.DHCP == nil || !clientservices.Enabled(n.Modules.DHCP.Enabled) {
		return n, errors.New("Tailnet requires enabled DNS and DHCP")
	}
	n.Modules.Tailnet = &clientservices.TailnetConfig{Enabled: true}
	r := tailnetReservation()
	hadTailnetIntent := c.Modules.Tailnet != nil && c.Modules.Tailnet.Enabled
	for _, x := range n.Modules.DHCP.Reservations {
		if x == r {
			if !hadTailnetIntent {
				return n, errors.New("Tailnet reservation already exists without Tailnet intent; refusing adoption")
			}
			continue
		}
		if x.Name == r.Name || strings.EqualFold(x.MAC, r.MAC) || x.Address == r.Address {
			return n, errors.New("Tailnet reservation conflicts with existing DHCP reservation")
		}
	}
	found := false
	for _, x := range n.Modules.DHCP.Reservations {
		if x == r {
			found = true
			break
		}
	}
	if !found {
		n.Modules.DHCP.Reservations = append(n.Modules.DHCP.Reservations, r)
	}
	return n, nil
}

const tailnetBuilderPath = "/opt/boetticher/current/controller/proxmox/libexec/boetticher-build-tailnet"

func validateTailnetAuthKeyFile(path string) error {
	if path == "" {
		return errors.New("Tailnet auth key file is required")
	}
	if err := pathguard.ValidateNoSymlinkComponents(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("Tailnet auth key path is not a private regular file")
	}
	return nil
}
func readTailnetAuthKey(path string) ([]byte, error) {
	if err := validateTailnetAuthKeyFile(path); err != nil {
		return nil, err
	}
	data, err := pathguard.ReadFileLimited(path, 16<<10)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		wipeTailnetAuthKey(data)
		return nil, errors.New("Tailnet auth key file is empty")
	}
	return trimmed, nil
}

func readTailnetAuthKeyPrompt(input io.Reader, errOut io.Writer) ([]byte, error) {
	file, ok := input.(*os.File)
	if !ok || file == nil || !term.IsTerminal(int(file.Fd())) {
		return nil, errors.New("Tailnet enrollment requires --auth-key-file when stdin is not a terminal")
	}
	fmt.Fprint(errOut, "Tailnet auth key: ")
	data, err := term.ReadPassword(int(file.Fd()))
	fmt.Fprintln(errOut)
	if err != nil {
		wipeTailnetAuthKey(data)
		return nil, fmt.Errorf("read Tailnet auth key: %w", err)
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		wipeTailnetAuthKey(data)
		return nil, errors.New("Tailnet auth key is empty")
	}
	return trimmed, nil
}

func wipeTailnetAuthKey(key []byte) {
	for i := range key {
		key[i] = 0
	}
}

const tailnetBuilderPrepareScript = `set -eu
p=$(mktemp -d /var/tmp/boetticher-tailnet-builder.XXXXXX)
case "$p" in
  /var/tmp/boetticher-tailnet-builder.*) ;;
  *) exit 1 ;;
esac
printf '%s\n' '{"version":1,"outer":true}' >"$p/.boetticher-build-owned"
: >"$p/.boetticher-build.lock"
chmod 600 "$p/.boetticher-build-owned" "$p/.boetticher-build.lock"
printf '%s\n' "$p"`

func buildTailnetImage(ctx context.Context, host firewallmodule.HostClient) (retErr error) {
	result, err := host.Run(ctx, tailnetBuilderPrepareScript)
	if err != nil {
		return fmt.Errorf("prepare Tailnet builder on Host: %w", err)
	}
	remote := strings.TrimSpace(string(result.Stdout))
	if remote == "" || strings.ContainsAny(remote, "\r\n\x00") || filepath.Dir(remote) != "/var/tmp" || !strings.HasPrefix(filepath.Base(remote), "boetticher-tailnet-builder.") {
		return errors.New("Host returned an unsafe Tailnet builder path")
	}
	remoteBuilder := remote + "/build-tailnet.sh"
	remoteHelper := remote + "/build-temp.py"
	cleanup := func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, cleanupErr := host.Run(cleanupCtx, "case "+tailnetShellQuote(remote)+" in /var/tmp/boetticher-tailnet-builder.*) exec 9>"+tailnetShellQuote(remote+"/.boetticher-build.lock")+"; flock -n 9; rm -rf -- "+tailnetShellQuote(remote)+";; *) exit 1;; esac"); cleanupErr != nil && retErr == nil {
			retErr = fmt.Errorf("cleanup Tailnet Host build directory: %w", cleanupErr)
		}
	}
	defer cleanup()
	if err := host.Copy(ctx, tailnetBuilderPath, remoteBuilder); err != nil {
		return fmt.Errorf("copy Tailnet builder to Host: %w", err)
	}
	if err := host.Copy(ctx, filepath.Join(filepath.Dir(tailnetBuilderPath), "build-temp.py"), remoteHelper); err != nil {
		return fmt.Errorf("copy build temporary helper to Host: %w", err)
	}
	if _, err := host.Run(ctx, "set -eu; exec 9>"+tailnetShellQuote(remote+"/.boetticher-build.lock")+"; flock -n 9; chmod 700 "+tailnetShellQuote(remoteBuilder)+" "+tailnetShellQuote(remoteHelper)+"; sh "+tailnetShellQuote(remoteBuilder)); err != nil {
		return fmt.Errorf("build Tailnet image: %w", err)
	}
	return nil
}
func tailnetShellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

func runTailnetApply(a []string, in io.Reader, out, errOut io.Writer) error {
	o, e := parseTailnetOptions("module tailnet apply", a, true)
	if e != nil {
		return e
	}
	if o.plan {
		return runTailnetPlan([]string{"--plan"}, out)
	}
	l, e := acquireClientServicesLock()
	if e != nil {
		return e
	}
	defer l.Release()
	sc, e := loadClientServiceContext()
	if e != nil {
		return e
	}
	n, e := prepareTailnet(sc.Config)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	provider, e := requireClientProvider(ctx, sc.Site, sc.Desired, sc.Host)
	if e != nil {
		return e
	}
	state, e := firewallmodule.ServiceStateFromModules(sc.Site, n.Modules)
	if e != nil {
		return e
	}
	if e = verifyClientServices(ctx, provider, state, tailnet.Module, missingTailnetDHCPSections(sc.Config, n, state)); e != nil {
		return fmt.Errorf("verify DNS/DHCP prerequisites: %w", e)
	}
	leases, leaseErr := readNativeDHCPLeases(ctx, sc.Host)
	if leaseErr != nil && !errors.Is(leaseErr, errLeaseFileAbsent) {
		return fmt.Errorf("inspect active DHCP leases: %w", leaseErr)
	}
	if leaseErr == nil {
		if conflict := tailnetLeaseConflict(tailnetReservation(), leases, time.Now().Unix()); conflict != nil {
			return conflict
		}
	}
	guest, e := tailnet.InspectGuest(ctx, sc.Host)
	if e != nil {
		return e
	}
	needsBuild := !guest.Exists
	enrollmentNeeded := needsBuild
	runtimeHealthy := false
	if guest.Exists {
		// An existing guest can be stopped or missing its runtime assets. Probe
		// those assets before native status so apply can repair that state before
		// enrollment. InspectGuest already proved the exact owned VMID 200
		// configuration; transport failures from the probe remain fatal.
		runtimeReady, runtimeErr := tailnet.RuntimeReadyState(ctx, sc.Host)
		if runtimeErr != nil {
			return runtimeErr
		}
		needsBuild = !runtimeReady
		if runtimeReady {
			report, statusErr := tailnet.ReadStatus(ctx, sc.Host)
			if statusErr != nil {
				return statusErr
			}
			runtimeHealthy = report.State == tailnet.Healthy
			enrollmentNeeded = report.NeedsAuth
		} else {
			// Runtime assets are replaceable, but the established node identity is
			// durable Tailscale state. Repair first and let the native post-repair
			// status prove whether enrollment is actually still required.
			enrollmentNeeded = false
		}
	}
	intentChanged := sc.Config.Modules.Tailnet == nil || !sc.Config.Modules.Tailnet.Enabled || len(sc.Config.Modules.DHCP.Reservations) != len(n.Modules.DHCP.Reservations)
	composed, e := composeClientAppliance(sc, n.Modules)
	if e != nil {
		return e
	}
	observedFirewall, e := provider.UCIGet(ctx, "firewall")
	if e != nil {
		return fmt.Errorf("inspect composed firewall policy: %w", e)
	}
	firewallChanges, e := firewallmodule.DiffFirewall(observedFirewall, composed.Firewall)
	if e != nil {
		return e
	}
	firewallAligned := len(firewallChanges) == 0
	if !intentChanged && guest.Exists && runtimeHealthy && !enrollmentNeeded && firewallAligned {
		return nil
	}
	if !o.yes {
		if in == nil {
			return errors.New("Tailnet apply requires --yes or confirmation")
		}
		ok, pe := promptYesNo(bufio.NewReader(in), out, "Enable Tailnet and reconcile the Host guest? [y/N]: ", false)
		if pe != nil || !ok {
			return errors.New("Tailnet apply cancelled")
		}
	}
	var key []byte
	if enrollmentNeeded {
		if o.authKeyFile != "" {
			key, e = readTailnetAuthKey(o.authKeyFile)
		} else {
			key, e = readTailnetAuthKeyPrompt(in, errOut)
		}
		if e != nil {
			return e
		}
		defer wipeTailnetAuthKey(key)
	}
	if intentChanged {
		if e = controllerhost.SaveConfig(n); e != nil {
			return e
		}
	}
	if _, _, e = reconcileClientServices(ctx, provider, sc, n.Modules); e != nil {
		return fmt.Errorf("reconcile DNS/DHCP prerequisites: %w", e)
	}
	if needsBuild {
		if e = buildTailnetImage(ctx, sc.Host); e != nil {
			return e
		}
	}
	if e = tailnet.CreateGuest(ctx, sc.Host); e != nil {
		return e
	}
	if e = tailnet.InstallRuntime(ctx, sc.Host); e != nil {
		return e
	}
	if e = tailnet.Configure(ctx, sc.Host, key); e != nil {
		return e
	}
	report, e := tailnet.ReadStatus(ctx, sc.Host)
	if e != nil {
		return e
	}
	if report.State != tailnet.Healthy {
		return fmt.Errorf("Tailnet apply verification is %s: %s", report.State, report.Detail)
	}
	_ = errOut
	fmt.Fprintln(out, "Tailnet: applied and verified")
	return nil
}
func runTailnetStatus(a []string, out io.Writer) error {
	o, e := parseTailnetOptions("module tailnet status", a, false)
	if e != nil {
		return e
	}
	c, e := controllerhost.LoadConfig()
	if e != nil {
		if o.json {
			writeTailnetReport(out, tailnet.NewReport(true, tailnet.Failed, e.Error()))
		}
		return e
	}
	if c.Modules.Tailnet == nil || !c.Modules.Tailnet.Enabled {
		r := tailnet.NewReport(false, tailnet.Off, "not configured")
		if o.json {
			b, _ := json.Marshal(r)
			fmt.Fprintln(out, string(b))
		} else {
			fmt.Fprintln(out, "Tailnet: OFF (not configured)")
		}
		return nil
	}
	sc, e := loadClientServiceContext()
	if e != nil {
		if o.json {
			writeTailnetReport(out, tailnet.NewReport(true, tailnet.Failed, e.Error()))
		}
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	r, e := tailnet.ReadStatus(ctx, sc.Host)
	if o.json {
		writeTailnetReport(out, r)
		if e != nil {
			return e
		}
		if r.State != tailnet.Healthy {
			return fmt.Errorf("tailnet status is %s", r.State)
		}
		return nil
	}
	if e != nil {
		return e
	}
	fmt.Fprintf(out, "Tailnet: %s\nReason: %s\n", strings.ToUpper(string(r.State)), r.Detail)
	if r.State != tailnet.Healthy {
		return fmt.Errorf("tailnet status is %s", r.State)
	}
	return nil
}
func writeTailnetReport(out io.Writer, r tailnet.Report) {
	b, _ := json.Marshal(r)
	_, _ = fmt.Fprintln(out, string(b))
}
func runTailnetTest(a []string, out io.Writer) error {
	o, e := parseTailnetOptions("module tailnet test", a, true)
	if e != nil {
		return e
	}
	if o.plan {
		fmt.Fprintln(out, "Tailnet test plan: local runtime and DNS TCP/UDP checks; remote and physical acceptance NOT TESTED")
		return nil
	}
	if !o.yes {
		return errors.New("Tailnet test requires --yes or --plan")
	}
	sc, e := loadClientServiceContext()
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	guest, e := tailnet.InspectGuest(ctx, sc.Host)
	if e != nil {
		return e
	}
	if !guest.Exists {
		return errors.New("Tailnet guest is absent; run module tailnet apply first")
	}
	report, e := tailnet.ReadStatus(ctx, sc.Host)
	if e != nil {
		return fmt.Errorf("Tailnet runtime status failed: %w", e)
	}
	if report.State != tailnet.Healthy {
		return fmt.Errorf("Tailnet runtime is %s: %s", report.State, report.Detail)
	}
	name := tailnet.GuestName + "." + strings.TrimSuffix(sc.Site.Network.Domain, ".")
	command := tailnet.GuestCommand("set -eu; dig +time=3 +tries=1 +short @" + tailnet.Resolver + " " + name + " A; dig +tcp +time=3 +tries=1 +short @" + tailnet.Resolver + " " + name + " A")
	result, e := sc.Host.Run(ctx, command)
	if e != nil {
		return fmt.Errorf("Tailnet DNS TCP/UDP checks failed: %w", e)
	}
	lines := strings.Fields(string(result.Stdout))
	if len(lines) != 2 || lines[0] != tailnet.GuestAddress || lines[1] != tailnet.GuestAddress {
		return errors.New("Tailnet DNS TCP/UDP checks returned an unexpected address")
	}
	fmt.Fprintln(out, "Tailnet local checks: PASS (runtime and DNS TCP/UDP)")
	fmt.Fprintln(out, "Remote, packet, and physical acceptance: NOT TESTED")
	return nil
}
func runTailnetTeardown(a []string, in io.Reader, out io.Writer) error {
	o, e := parseTailnetOptions("module tailnet teardown", a, true)
	if e != nil {
		return e
	}
	l, e := acquireClientServicesLock()
	if e != nil {
		return e
	}
	defer l.Release()
	sc, e := loadClientServiceContext()
	if e != nil {
		return e
	}
	c := sc.Config
	proposed := c
	proposed.Modules = c.Modules.Clone()
	if proposed.Modules.Tailnet != nil {
		proposed.Modules.Tailnet.Enabled = false
	}
	if proposed.Modules.DHCP != nil {
		kept := make([]clientservices.Reservation, 0, len(proposed.Modules.DHCP.Reservations))
		for _, r := range proposed.Modules.DHCP.Reservations {
			owned := r.Name == tailnet.GuestName || strings.EqualFold(r.MAC, tailnet.GuestMAC) || r.Address == tailnet.GuestAddress
			if owned && r != tailnetReservation() {
				return errors.New("Tailnet reservation is not the exact owned reservation; refusing teardown")
			}
			if !owned {
				kept = append(kept, r)
			}
		}
		proposed.Modules.DHCP.Reservations = kept
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	guest, e := tailnet.InspectGuest(ctx, sc.Host)
	if e != nil {
		return e
	}
	if o.plan {
		fmt.Fprintf(out, "Tailnet teardown plan: disable intent, remove exact owned reservation, guest present=%v; preserve services\n", guest.Exists)
		return nil
	}
	if !o.yes {
		if in == nil {
			return errors.New("Tailnet teardown requires --yes or confirmation")
		}
		ok, pe := promptYesNo(bufio.NewReader(in), out, "Disable Tailnet? [y/N]: ", false)
		if pe != nil || !ok {
			return errors.New("Tailnet teardown cancelled")
		}
	}
	provider, e := requireClientProvider(ctx, sc.Site, sc.Desired, sc.Host)
	if e != nil {
		return e
	}
	if e = controllerhost.SaveConfig(proposed); e != nil {
		return e
	}
	state, e := firewallmodule.ServiceStateFromModules(sc.Site, proposed.Modules)
	if e != nil {
		return e
	}
	if _, _, e = reconcileClientServices(ctx, provider, sc, proposed.Modules); e != nil {
		return fmt.Errorf("Tailnet intent saved but provider reconciliation failed: %w", e)
	}
	if e = tailnet.Teardown(ctx, sc.Host); e != nil {
		return fmt.Errorf("Tailnet intent and provider reconciled but guest teardown failed: %w", e)
	}
	if g, verifyErr := tailnet.InspectGuest(ctx, sc.Host); verifyErr != nil {
		return verifyErr
	} else if g.Exists {
		return errors.New("Tailnet guest remains after teardown")
	}
	if e = verifyClientServices(ctx, provider, state, tailnet.Module); e != nil {
		return fmt.Errorf("Tailnet teardown verification failed: %w", e)
	}
	fmt.Fprintln(out, "Tailnet: disabled and verified")
	return nil
}
