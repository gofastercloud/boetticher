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
)

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
	for _, s := range c.Modules.Systems {
		fmt.Fprintf(out, "%s VMID=%d %s %s:%d check=%t\n", s.Name, s.VMID, s.Kind, s.Address, s.Port, s.Monitoring)
	}
	return nil
}

func systemStatus(args []string, out io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: boetticher host system-status NAME")
	}
	c, e := systemsLoadConfig()
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	transport, transportErr := systemsTransportFor(c)
	for _, s := range c.Modules.Systems {
		if strings.EqualFold(s.Name, args[0]) {
			observed := "unavailable"
			if transportErr == nil {
				if inv, ie := systemsCollect(ctx, transport, false); ie == nil {
					for _, g := range inv.Guests {
						if g.VMID == s.VMID {
							_, mac, bridge, tag, ce := systemsInspectGuest(ctx, transport, g)
							if ce == nil && g.Type == s.Kind && g.Name == s.GuestName && strings.EqualFold(mac, s.MAC) && bridge == "vmbr1" && tag == "20" {
								observed = "identity matches"
							} else {
								observed = "identity drift"
							}
						}
					}
				} else {
					observed = "host unavailable"
				}
			} else {
				observed = "host unavailable"
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
							if ready, ge := (observability.HostClient{Transport: transport}).GatusSystemsHealthy(ctx, c.Modules.Systems); ge != nil || !ready {
								observed = "monitoring drift"
							}
						}
					} else {
						observed = "provider unavailable: " + pe.Error()
					}
				} else {
					observed = "provider context unavailable: " + ce.Error()
				}
			}
			fmt.Fprintf(out, "System %s\n  Guest     %s VMID %d (%s)\n  Network   SERVERS %s MAC %s\n  Port      %d\n  Monitoring %s\n", s.Name, s.GuestName, s.VMID, s.Kind, s.Address, s.MAC, s.Port, map[bool]string{true: "configured", false: "disabled"}[s.Monitoring])
			fmt.Fprintf(out, "  Observed  %s\n", observed)
			return nil
		}
	}
	return fmt.Errorf("no registered system named %s", args[0])
}

func registerSystem(args []string, input io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher host register-system NAME --vmid VMID --address IPv4 --port PORT [--check] [--plan|--yes]")
	}
	name := strings.ToLower(args[0])
	fs := flag.NewFlagSet("host register-system", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	vmid := fs.Int("vmid", 0, "")
	address := fs.String("address", "", "")
	port := fs.Int("port", 0, "")
	check := fs.Bool("check", false, "")
	plan := fs.Bool("plan", false, "")
	yes := fs.Bool("yes", false, "")
	if e := fs.Parse(args[1:]); e != nil || fs.NArg() != 0 {
		return errors.New("usage: boetticher host register-system NAME --vmid VMID --address IPv4 --port PORT [--check] [--plan|--yes]")
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
		if strings.EqualFold(s.Name, name) && (s.VMID != *vmid || s.Address != *address || s.Port != *port || s.Monitoring != *check) {
			return fmt.Errorf("system name %s already exists with a conflicting definition", name)
		}
	}
	if *vmid <= 0 || *port < 1 || *port > 65535 {
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
	s := clientservices.System{Name: name, VMID: *vmid, Kind: kind, GuestName: found.Name, MAC: mac, Address: *address, Port: *port, Monitoring: *check}
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
	return client.ReconcileGatus(ctx, []byte(config), modules.Systems)
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
