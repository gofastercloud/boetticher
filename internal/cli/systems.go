package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/gofastercloud/boetticher/internal/clientservices"
	host "github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/firewallmodule"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/observability"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// Narrow seams keep command-flow tests independent of an installed Controller
// and Host. Production paths retain the concrete Host and provider contracts.
var (
	systemsLoadConfig               = host.LoadConfig
	systemsSaveConfig               = host.SaveConfig
	systemsTransportFor             = host.TransportFor
	systemsCollect                  = host.Collect
	systemsInspectGuest             = inspectSystemGuest
	systemsReadNativeDHCPLeases     = readNativeDHCPLeases
	systemsLoadClientServiceContext = loadClientServiceContext
	systemsAcquireLock              = func() (func(), error) {
		lock, err := acquireClientServicesLock()
		if err != nil {
			return nil, err
		}
		return func() { _ = lock.Release() }, nil
	}
	// systemsRun carries the bounded power-state reads and the explicit
	// start/shutdown action over the strict Host transport.
	systemsRun = func(ctx context.Context, t host.Transport, command string) (host.Result, error) {
		return t.Run(ctx, command)
	}
	systemsSleep = func(ctx context.Context, d time.Duration) error {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	}
)

// A Host inventory and the exact guest config are several sequential SSH
// observations. Keep one bounded budget for the complete read instead of
// expiring while the final identity check is still in flight.
const systemInspectionTimeout = 60 * time.Second

// Power changes use Proxmox's own bounded start and graceful shutdown. The
// shutdown timeout is passed to Proxmox; the SSH command budget exceeds it so
// Proxmox, not the transport, decides a shutdown timeout. A settled state is
// then confirmed with the exact guest's native status.
const (
	systemShutdownTimeout     = 60 * time.Second
	systemPowerCommandTimeout = systemShutdownTimeout + 30*time.Second
	systemPowerSettleInterval = 2 * time.Second
	systemPowerSettleAttempts = 30
)

var errSystemsHostUnavailable = errors.New("host unavailable")

func runSystems(args []string, input io.Reader, out, errOut io.Writer) error {
	switch args[0] {
	case "list-systems":
		return listSystems(args[1:], out)
	case "system-status":
		return systemStatus(args[1:], out)
	case "register-system":
		return registerSystem(args[1:], input, out)
	case "unregister-system":
		return unregisterSystem(args[1:], input, out)
	case "start-system":
		return changeSystemPower(args[1:], out, true)
	case "stop-system":
		return changeSystemPower(args[1:], out, false)
	}
	return errors.New("unknown system command")
}

func listSystems(args []string, out io.Writer) error {
	if len(args) != 0 {
		return errors.New("usage: boetticher host list-systems")
	}
	c, e := systemsLoadConfig()
	if e != nil {
		return e
	}
	// One bounded Proxmox inventory read supplies every registration's power state.
	// Identity is not re-proven here; host system-status does that.
	var guests map[int]host.Guest
	var powerErr error
	if len(c.Modules.Systems) != 0 {
		ctx, cancel := context.WithTimeout(context.Background(), systemInspectionTimeout)
		defer cancel()
		transport, te := systemsTransportFor(c)
		if te == nil {
			var inv host.Inventory
			if inv, te = systemsCollect(ctx, transport, false); te == nil {
				guests = map[int]host.Guest{}
				for _, g := range inv.Guests {
					guests[g.VMID] = g
				}
			}
		}
		powerErr = te
		for _, s := range c.Modules.Systems {
			power := "unavailable"
			if g, ok := guests[s.VMID]; ok {
				power = guestPowerLabel(g.Status) + " onboot=" + systemOnBoot(ctx, transport, g)
			} else if guests != nil {
				power = "missing"
			}
			listSystemLine(out, s, power)
		}
	}
	if powerErr != nil {
		fmt.Fprintf(out, "Power state unavailable: %v\n", powerErr)
	}
	return nil
}

func listSystemLine(out io.Writer, s clientservices.System, power string) {
	if s.HomePort != 0 {
		fmt.Fprintf(out, "%s VMID=%d %s %s:%d home-port=%d", s.Name, s.VMID, s.Kind, s.Address, s.Port, s.HomePort)
	} else {
		fmt.Fprintf(out, "%s VMID=%d %s %s:%d", s.Name, s.VMID, s.Kind, s.Address, s.Port)
	}
	if s.DNSName != "" {
		fmt.Fprintf(out, " dns-name=%s", s.DNSName)
	}
	fmt.Fprintf(out, " check=%t power=%s\n", s.Monitoring, power)
}

// guestPowerLabel keeps Proxmox's own state word; an empty state is unknown,
// never running.
func guestPowerLabel(status string) string {
	if status = strings.TrimSpace(status); status == "" {
		return "unknown"
	}
	return status
}

// systemOnBoot reads the guest's native onboot flag; a failed read is
// reported as unknown rather than assumed.
func systemOnBoot(ctx context.Context, transport host.Transport, g host.Guest) string {
	command, err := host.GuestConfigCommand(g.Node, g)
	if err != nil {
		return "unknown"
	}
	output, err := systemsRun(ctx, transport, command)
	if err != nil {
		return "unknown"
	}
	policy, err := host.ParseGuestBootPolicy(g, output.Stdout)
	if err != nil {
		return "unknown"
	}
	return map[bool]string{true: "yes", false: "no"}[policy.OnBoot]
}

// verifySystemGuest re-proves one registration's saved identity against the
// current Proxmox inventory and the exact guest configuration: one guest at
// the VMID in the user range, the same kind, name, and MAC, one SERVERS NIC,
// and no product ownership tag.
func verifySystemGuest(ctx context.Context, transport host.Transport, s clientservices.System) (host.Guest, error) {
	if s.VMID < model.UserGuestIDMin || s.VMID > model.UserGuestIDMax {
		return host.Guest{}, fmt.Errorf("VMID %d is outside the user-workload range %d-%d", s.VMID, model.UserGuestIDMin, model.UserGuestIDMax)
	}
	inv, err := systemsCollect(ctx, transport, false)
	if err != nil {
		return host.Guest{}, fmt.Errorf("%w: %v", errSystemsHostUnavailable, err)
	}
	var found host.Guest
	matches := 0
	for _, g := range inv.Guests {
		if g.VMID == s.VMID {
			found = g
			matches++
		}
	}
	switch {
	case matches == 0:
		return host.Guest{}, fmt.Errorf("guest VMID %d was not found", s.VMID)
	case matches > 1:
		return host.Guest{}, fmt.Errorf("VMID %d matches multiple guests", s.VMID)
	}
	kind, mac, bridge, tag, err := systemsInspectGuest(ctx, transport, found)
	if err != nil {
		return found, fmt.Errorf("identity drift: %w", err)
	}
	if found.Type != s.Kind || kind != s.Kind || found.Name != s.GuestName || !strings.EqualFold(mac, s.MAC) || bridge != "vmbr1" || tag != "20" {
		return found, fmt.Errorf("identity drift (guest=%s/%s kind=%s mac=%s bridge=%s tag=%s)", found.Name, s.GuestName, kind, mac, bridge, tag)
	}
	return found, nil
}

func systemStatus(args []string, out io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: boetticher host system-status NAME")
	}
	c, e := systemsLoadConfig()
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), systemInspectionTimeout)
	defer cancel()
	for _, s := range c.Modules.Systems {
		if strings.EqualFold(s.Name, args[0]) {
			observed, power, running := "host unavailable", "unavailable", false
			transport, transportErr := systemsTransportFor(c)
			if transportErr == nil {
				guest, ie := verifySystemGuest(ctx, transport, s)
				switch {
				case ie == nil:
					observed = "identity matches"
				case errors.Is(ie, errSystemsHostUnavailable):
					observed = "host unavailable"
				default:
					observed = ie.Error()
				}
				if guest.VMID != 0 {
					power = guestPowerLabel(guest.Status) + " (onboot " + systemOnBoot(ctx, transport, guest) + ")"
					running = guest.Status == "running"
				}
			}
			if observed == "identity matches" {
				if sc, ce := systemsLoadClientServiceContext(); ce == nil {
					if provider, pe := requireClientProvider(ctx, sc.Site, sc.Desired, sc.Host); pe == nil {
						if changes, se := clientServiceChangeCount(ctx, provider, sc, c.Modules); se != nil {
							observed = "provider composition unavailable: " + se.Error()
						} else if changes != 0 {
							observed = "provider composition drift"
						}
						if s.Monitoring && observed == "identity matches" {
							// Include media intent so the read-only gate accounts for every
							// owned Gatus endpoint, not only operator-managed systems.
							if ready, ge := (observability.HostClient{Transport: transport}).GatusSystemsHealthy(ctx, c.Modules.Systems, c.Modules); ge != nil || !ready {
								observed = "monitoring drift"
							}
						}
						_ = provider.Close()
					} else {
						observed = "provider unavailable: " + pe.Error()
					}
				} else {
					observed = "provider context unavailable: " + ce.Error()
				}
			}
			fmt.Fprintf(out, "System %s\n  Guest     %s VMID %d (%s)\n  Network   SERVERS %s MAC %s\n  Port      %d\n", s.Name, s.GuestName, s.VMID, s.Kind, s.Address, s.MAC, s.Port)
			if s.HomePort != 0 {
				fmt.Fprintf(out, "  HOME      TCP %d -> SERVERS %s:%d\n", s.HomePort, s.Address, s.Port)
			}
			if s.DNSName != "" {
				fmt.Fprintf(out, "  DNS       %s -> %s.%s\n", s.DNSName, s.Name, labConfigDomain(c))
			}
			fmt.Fprintf(out, "  Monitoring %s\n", map[bool]string{true: "configured", false: "disabled"}[s.Monitoring])
			fmt.Fprintf(out, "  Power     %s\n", power)
			fmt.Fprintf(out, "  Observed  %s\n", observed)
			fmt.Fprintf(out, "  Result    %s\n", systemStatusResult(s.Name, observed, power, running))
			return nil
		}
	}
	return fmt.Errorf("no registered system named %s", args[0])
}

// systemStatusResult is PASS only with current identity, provider, and
// monitoring evidence and a running guest. A stopped guest is never hidden
// behind a matching identity.
func systemStatusResult(name, observed, power string, running bool) string {
	switch {
	case observed == "host unavailable":
		return "UNKNOWN Host unavailable"
	case strings.HasPrefix(observed, "identity drift") || strings.HasPrefix(observed, "guest VMID") || strings.HasPrefix(observed, "VMID"):
		return "FAIL " + observed
	case !running:
		return fmt.Sprintf("FAIL guest is %s; start it with: boetticher host start-system %s --plan", strings.SplitN(power, " ", 2)[0], name)
	case observed != "identity matches":
		return "FAIL " + observed
	}
	return "PASS"
}

func registerSystem(args []string, input io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher host register-system NAME --vmid VMID --address IPv4 --port PORT [--home-port PORT] [--dns-name FQDN] [--check] [--plan|--yes]")
	}
	name := strings.ToLower(args[0])
	fs := flag.NewFlagSet("host register-system", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	vmid := fs.Int("vmid", 0, "")
	address := fs.String("address", "", "")
	port := fs.Int("port", 0, "")
	homePort := fs.Int("home-port", 0, "")
	dnsName := fs.String("dns-name", "", "")
	check := fs.Bool("check", false, "")
	plan := fs.Bool("plan", false, "")
	yes := fs.Bool("yes", false, "")
	if e := fs.Parse(args[1:]); e != nil || fs.NArg() != 0 {
		return errors.New("usage: boetticher host register-system NAME --vmid VMID --address IPv4 --port PORT [--home-port PORT] [--dns-name FQDN] [--check] [--plan|--yes]")
	}
	if *plan && *yes {
		return errors.New("--plan cannot be combined with --yes")
	}
	var e error
	if *yes {
		var release func()
		release, e = systemsAcquireLock()
		if e != nil {
			return e
		}
		defer release()
	}
	c, e := systemsLoadConfig()
	if e != nil {
		return e
	}
	for _, s := range c.Modules.Systems {
		if strings.EqualFold(s.Name, name) && (s.VMID != *vmid || s.Address != *address || s.Port != *port || s.HomePort != *homePort || s.Monitoring != *check) {
			return fmt.Errorf("system name %s already exists with a conflicting definition", name)
		}
	}
	if *homePort == 443 {
		return errors.New("HOME publication port 443 is reserved for firewall management")
	}
	if *vmid <= 0 || *port < 1 || *port > 65535 || *homePort < 0 || *homePort > 65535 {
		return errors.New("VMID and port are invalid")
	}
	ip := net.ParseIP(*address)
	if ip == nil || ip.To4() == nil || ip.To4().String() != *address || !strings.HasPrefix(*address, "10.10.20.") {
		return errors.New("address must be a canonical SERVERS IPv4 address")
	}
	transport, e := systemsTransportFor(c)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), systemInspectionTimeout)
	defer cancel()
	inv, e := systemsCollect(ctx, transport, false)
	if e != nil {
		return e
	}
	var found host.Guest
	for _, g := range inv.Guests {
		if g.VMID == *vmid {
			if found.VMID != 0 {
				return errors.New("VMID matches multiple guests")
			}
			found = g
		}
	}
	if found.VMID == 0 {
		return fmt.Errorf("guest VMID %d was not found", *vmid)
	}
	kind, mac, bridge, tag, e := systemsInspectGuest(ctx, transport, found)
	if e != nil {
		return e
	}
	if bridge != "vmbr1" || tag != "20" {
		return errors.New("guest must have exactly one SERVERS NIC on vmbr1 VLAN 20")
	}
	if mac == "" {
		return errors.New("guest SERVERS NIC has no MAC")
	}
	s := clientservices.System{Name: name, VMID: *vmid, Kind: kind, GuestName: found.Name, MAC: mac, Address: *address, Port: *port, HomePort: *homePort, DNSName: strings.TrimSpace(*dnsName), Monitoring: *check}
	if *vmid < model.UserGuestIDMin || *vmid > model.UserGuestIDMax {
		return fmt.Errorf("VMID must be in the user-workload range %d-%d", model.UserGuestIDMin, model.UserGuestIDMax)
	}
	leases, leaseErr := systemsReadNativeDHCPLeases(ctx, firewallmodule.HostClient{Transport: transport})
	if leaseErr != nil && !errors.Is(leaseErr, errLeaseFileAbsent) {
		return fmt.Errorf("inspect active DHCP leases: %w", leaseErr)
	}
	for _, lease := range leases {
		if lease.Expiry != 0 && lease.Expiry <= time.Now().Unix() {
			continue
		}
		leaseMAC, _ := clientservices.CanonicalMAC(lease.MAC)
		if (lease.Address == s.Address || strings.EqualFold(lease.Hostname, s.Name)) && leaseMAC != s.MAC {
			return fmt.Errorf("active DHCP lease conflicts with system %s", name)
		}
	}
	existingIndex := -1
	for index, old := range c.Modules.Systems {
		if strings.EqualFold(old.Name, name) {
			if old.Kind != s.Kind || old.GuestName != s.GuestName || !strings.EqualFold(old.MAC, s.MAC) {
				return fmt.Errorf("registered system %s guest identity changed; unregister and register it again explicitly", name)
			}
			existingIndex = index
			continue
		}
		if old.VMID == s.VMID || strings.EqualFold(old.MAC, s.MAC) || old.Address == s.Address {
			return errors.New("system identity conflicts with another registration")
		}
		if s.HomePort != 0 && old.HomePort == s.HomePort {
			return fmt.Errorf("home publication port %d is already used by system %s", s.HomePort, old.Name)
		}
	}
	proposed := c
	if existingIndex >= 0 {
		proposed.Modules.Systems = append([]clientservices.System(nil), c.Modules.Systems...)
		proposed.Modules.Systems[existingIndex] = s
	} else {
		proposed.Modules.Systems = append(append([]clientservices.System(nil), c.Modules.Systems...), s)
	}
	if e := host.ValidateConfig(proposed); e != nil {
		return e
	}
	fmt.Fprintf(out, "System %s\n  Guest %s VMID %d (%s)\n  Network SERVERS vmbr1:20 %s -> %s\n  Port %d\n", name, found.Name, *vmid, kind, mac, *address, *port)
	if *homePort != 0 {
		fmt.Fprintf(out, "  HOME publication TCP %d -> %s:%d\n", *homePort, *address, *port)
	}
	if s.DNSName != "" {
		fmt.Fprintf(out, "  DNS name %s -> %s.<lab-domain>\n", s.DNSName, name)
	}
	if *check {
		fmt.Fprintln(out, "  Monitoring requested")
	}
	if *plan {
		return nil
	}
	if !*yes {
		return errors.New("host register-system requires --yes or --plan")
	}
	if e := systemsSaveConfig(proposed); e != nil {
		return e
	}
	serviceContext, e := systemsLoadClientServiceContext()
	if e != nil {
		fmt.Fprintln(out, "Registration: saved; application deferred")
		return e
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel2()
	provider, e := requireClientProvider(ctx2, serviceContext.Site, serviceContext.Desired, serviceContext.Host)
	if e != nil {
		fmt.Fprintln(out, "Registration: saved; application deferred")
		return e
	}
	defer provider.Close()
	serviceContext.Config = proposed
	if _, _, e = reconcileClientServices(ctx2, provider, serviceContext, proposed.Modules); e != nil {
		fmt.Fprintln(out, "Registration: saved; application failed")
		return e
	}
	// A disabled check must not make a registration depend on an unrelated
	// observability outage. A later normal observability apply prunes its check.
	monitoringNeeded := *check
	if e = reconcileSystemMonitoring(ctx2, serviceContext.Host.Transport, proposed.Modules, monitoringNeeded); e != nil {
		fmt.Fprintln(out, "Registration: saved; application failed")
		return e
	}
	state, se := firewallmodule.ServiceStateFromModules(serviceContext.Site, proposed.Modules)
	if se == nil {
		se = verifyClientServices(ctx2, provider, state, "dhcp")
	}
	if se != nil {
		fmt.Fprintln(out, "Registration: saved; application failed")
		return se
	}
	fmt.Fprintln(out, "Registration: PASS")
	_ = input
	return nil
}

func unregisterSystem(args []string, input io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher host unregister-system NAME --plan|--yes")
	}
	fs := flag.NewFlagSet("host unregister-system", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	plan := fs.Bool("plan", false, "")
	yes := fs.Bool("yes", false, "")
	if e := fs.Parse(args[1:]); e != nil || fs.NArg() != 0 || !*plan && !*yes || *plan && *yes {
		return errors.New("usage: boetticher host unregister-system NAME --plan|--yes")
	}
	if *yes {
		var release func()
		var e error
		release, e = systemsAcquireLock()
		if e != nil {
			return e
		}
		defer release()
	}
	c, e := systemsLoadConfig()
	if e != nil {
		return e
	}
	idx := -1
	for i, s := range c.Modules.Systems {
		if strings.EqualFold(s.Name, args[0]) {
			idx = i
			break
		}
	}
	if idx < 0 {
		if *plan {
			fmt.Fprintf(out, "System %s is already absent; no mutation\n", strings.ToLower(args[0]))
			return nil
		}
		serviceContext, loadErr := systemsLoadClientServiceContext()
		if loadErr != nil {
			return loadErr
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		provider, providerErr := requireClientProvider(ctx, serviceContext.Site, serviceContext.Desired, serviceContext.Host)
		if providerErr != nil {
			return providerErr
		}
		defer provider.Close()
		if _, _, reconcileErr := reconcileClientServices(ctx, provider, serviceContext, serviceContext.Config.Modules); reconcileErr != nil {
			return reconcileErr
		}
		if monitoringErr := reconcileSystemMonitoring(ctx, serviceContext.Host.Transport, serviceContext.Config.Modules, true); monitoringErr != nil {
			return monitoringErr
		}
		fmt.Fprintf(out, "Unregistration: PASS (system %s already absent; desired state reconciled)\n", strings.ToLower(args[0]))
		return nil
	}
	s := c.Modules.Systems[idx]
	fmt.Fprintf(out, "Remove network intent for %s (%s %s)\n", s.Name, s.GuestName, s.Address)
	if *plan {
		return nil
	}
	c.Modules.Systems = append(c.Modules.Systems[:idx], c.Modules.Systems[idx+1:]...)
	if e := systemsSaveConfig(c); e != nil {
		return e
	}
	serviceContext, e := systemsLoadClientServiceContext()
	if e != nil {
		fmt.Fprintln(out, "Unregistration: saved; application deferred")
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	provider, e := requireClientProvider(ctx, serviceContext.Site, serviceContext.Desired, serviceContext.Host)
	if e != nil {
		fmt.Fprintln(out, "Unregistration: saved; application deferred")
		return e
	}
	defer provider.Close()
	if _, _, e = reconcileClientServices(ctx, provider, serviceContext, c.Modules); e != nil {
		fmt.Fprintln(out, "Unregistration: saved; application failed")
		return e
	}
	if e = reconcileSystemMonitoring(ctx, serviceContext.Host.Transport, c.Modules, s.Monitoring); e != nil {
		fmt.Fprintln(out, "Unregistration: saved; application failed")
		return e
	}
	fmt.Fprintln(out, "Unregistration: PASS")
	_ = input
	return nil
}

func reconcileSystemMonitoring(ctx context.Context, transport host.Transport, modules clientservices.Modules, needed bool) error {
	if !needed {
		return nil
	}
	if !observability.Enabled(modules) {
		for _, system := range modules.Systems {
			if system.Monitoring {
				return errors.New("monitored systems require enabled observability")
			}
		}
		return nil
	}
	client := observability.HostClient{Transport: transport}
	config, err := client.GatusConfigStatus(ctx)
	if err != nil {
		return fmt.Errorf("read Gatus configuration: %w", err)
	}
	return client.ReconcileGatus(ctx, []byte(config), modules.Systems, modules)
}

func inspectSystemGuest(ctx context.Context, t host.Transport, g host.Guest) (kind, mac, bridge, tag string, err error) {
	kind = g.Type
	cmd := "qm config " + strconv.Itoa(g.VMID)
	if kind == "lxc" {
		cmd = "pct config " + strconv.Itoa(g.VMID)
	}
	r, e := t.Run(ctx, cmd)
	if e != nil {
		return "", "", "", "", e
	}
	nicCount := 0
	for _, line := range strings.Split(string(r.Stdout), "\n") {
		if strings.HasPrefix(line, "tags:") && strings.Contains(strings.ToLower(line), "boetticher") {
			return "", "", "", "", errors.New("product-owned guest cannot be registered")
		}
		if !strings.HasPrefix(line, "net") {
			continue
		}
		nicCount++
		if nicCount > 1 {
			return "", "", "", "", errors.New("guest has multiple NICs; registration requires one")
		}
		fields := strings.SplitN(line, ":", 2)
		if len(fields) != 2 {
			return "", "", "", "", errors.New("malformed guest NIC configuration")
		}
		v := strings.TrimSpace(fields[1])
		parts := strings.Split(v, ",")
		for _, p := range parts {
			kv := strings.SplitN(p, "=", 2)
			if len(kv) != 2 {
				continue
			}
			switch kv[0] {
			case "bridge":
				bridge = kv[1]
			case "tag":
				tag = kv[1]
			case "ip":
				if kind == "lxc" && kv[1] != "dhcp" {
					return "", "", "", "", errors.New("LXC registration requires DHCP addressing; remove the static Proxmox IP setting")
				}
			case "hwaddr", "macaddr", "virtio", "e1000", "rtl8139":
				mac = strings.ToLower(kv[1])
			}
		}
	}
	if bridge == "" {
		return "", "", "", "", errors.New("guest has no configured NIC")
	}
	return
}

// changeSystemPower starts or gracefully shuts down one registered
// operator-managed guest. Power state is the only guest property Boetticher
// changes: it never creates, deletes, reconfigures, updates, or backs up the
// guest. The saved identity is re-proven before any action, an already
// settled guest is a read-only no-op, and --plan never mutates.
func changeSystemPower(args []string, out io.Writer, start bool) error {
	action, desired, label := "stop-system", "stopped", "Stop"
	if start {
		action, desired, label = "start-system", "running", "Start"
	}
	usage := fmt.Errorf("usage: boetticher host %s NAME --plan|--yes", action)
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return usage
	}
	fs := flag.NewFlagSet("host "+action, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	plan := fs.Bool("plan", false, "")
	yes := fs.Bool("yes", false, "")
	if e := fs.Parse(args[1:]); e != nil || fs.NArg() != 0 || *plan == *yes {
		return usage
	}
	if *yes {
		release, e := systemsAcquireLock()
		if e != nil {
			return e
		}
		defer release()
	}
	c, e := systemsLoadConfig()
	if e != nil {
		return e
	}
	var s clientservices.System
	for _, candidate := range c.Modules.Systems {
		if strings.EqualFold(candidate.Name, args[0]) {
			s = candidate
		}
	}
	if s.Name == "" {
		return fmt.Errorf("no registered system named %s; only registered systems can be started or stopped", args[0])
	}
	transport, e := systemsTransportFor(c)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), systemInspectionTimeout+systemPowerCommandTimeout+systemPowerSettleInterval*systemPowerSettleAttempts)
	defer cancel()
	guest, e := verifySystemGuest(ctx, transport, s)
	if e != nil {
		return fmt.Errorf("%s refused for system %s: %w; the guest was not changed", action, s.Name, e)
	}
	state, e := readSystemPower(ctx, transport, s)
	if e != nil {
		return fmt.Errorf("read power state of system %s: %w; the guest was not changed", s.Name, e)
	}
	onboot := systemOnBoot(ctx, transport, guest)
	fmt.Fprintf(out, "System %s\n  Guest     %s VMID %d (%s)\n  Identity  matches registration\n  Power     %s (onboot %s)\n", s.Name, s.GuestName, s.VMID, s.Kind, state, onboot)
	if state == desired {
		fmt.Fprintf(out, "No change: system %s is already %s\n", s.Name, desired)
		return nil
	}
	if state != "running" && state != "stopped" {
		return fmt.Errorf("%s refused for system %s: guest is %s; Boetticher only starts a stopped guest or shuts down a running one", action, s.Name, state)
	}
	command := systemPowerCommand(s, start)
	fmt.Fprintf(out, "  Action    %s\n", command)
	if !start {
		if s.Monitoring {
			fmt.Fprintln(out, "  NOTE      its monitoring check reports it down until it is started again")
		}
		if onboot == "yes" {
			fmt.Fprintln(out, "  NOTE      onboot is enabled; Proxmox starts it again at the next Host boot")
		}
	}
	if *plan {
		fmt.Fprintln(out, "Plan only. The guest was not changed.")
		return nil
	}
	actionTransport := transport
	actionTransport.Timeout = systemPowerCommandTimeout
	result, runErr := systemsRun(ctx, actionTransport, command)
	if runErr != nil && result.ExitCode != 255 && result.ExitCode != -1 && !errors.Is(runErr, context.DeadlineExceeded) {
		// Proxmox definitely refused or timed out; report the observed state.
		now, _ := readSystemPower(ctx, transport, s)
		fmt.Fprintf(out, "%s-system: FAIL (guest is %s)\n", label, guestPowerLabel(now))
		return fmt.Errorf("%s: %w", command, runErr)
	}
	// An SSH drop may have lost the reply of an accepted request; only the
	// guest's native status decides the result.
	last := state
	for attempt := 0; attempt < systemPowerSettleAttempts; attempt++ {
		if now, re := readSystemPower(ctx, transport, s); re == nil {
			last = now
			if now == desired {
				fmt.Fprintf(out, "%s-system: PASS (system %s is %s)\n", label, s.Name, desired)
				return nil
			}
		}
		if e := systemsSleep(ctx, systemPowerSettleInterval); e != nil {
			break
		}
	}
	fmt.Fprintf(out, "%s-system: FAIL (guest is %s)\n", label, guestPowerLabel(last))
	if runErr != nil {
		return fmt.Errorf("%s: %w", command, runErr)
	}
	return fmt.Errorf("system %s did not become %s within %s", s.Name, desired, systemPowerSettleInterval*systemPowerSettleAttempts)
}

// systemPowerCommand is the exact Proxmox-native action for the registered
// kind. Shutdown is graceful and bounded; it never escalates to a forced stop.
func systemPowerCommand(s clientservices.System, start bool) string {
	tool := "qm"
	if s.Kind == "lxc" {
		tool = "pct"
	}
	if start {
		return fmt.Sprintf("%s start %d", tool, s.VMID)
	}
	return fmt.Sprintf("%s shutdown %d --timeout %d", tool, s.VMID, int(systemShutdownTimeout/time.Second))
}

// readSystemPower reads the exact guest's current native status rather than
// the cluster resource listing, which lags state changes.
func readSystemPower(ctx context.Context, transport host.Transport, s clientservices.System) (string, error) {
	if s.Kind != "lxc" && s.Kind != "qemu" {
		return "", fmt.Errorf("unsupported guest kind %q", s.Kind)
	}
	tool := "qm"
	if s.Kind == "lxc" {
		tool = "pct"
	}
	result, err := systemsRun(ctx, transport, fmt.Sprintf("%s status %d", tool, s.VMID))
	if err != nil {
		return "", err
	}
	state, ok := strings.CutPrefix(strings.TrimSpace(string(result.Stdout)), "status: ")
	if !ok || state == "" || strings.ContainsAny(state, " \n") {
		return "", errors.New("unrecognised guest status output")
	}
	return state, nil
}
