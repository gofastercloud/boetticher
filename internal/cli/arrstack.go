package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/arrstack"
	"github.com/gofastercloud/boetticher/internal/clientservices"
	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/firewallmodule"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/observability"
	"github.com/gofastercloud/boetticher/internal/openwrt"
	"github.com/gofastercloud/boetticher/internal/pathguard"
	"github.com/gofastercloud/boetticher/internal/site"
)

func runArrstackCapability(action string, args []string, input io.Reader, out, _ io.Writer) error {
	fs := flag.NewFlagSet("module media "+action, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	yes := fs.Bool("yes", false, "approve the change")
	plan := fs.Bool("plan", false, "preview without changing state")
	cloudflareTokenFile := fs.String("cloudflare-token-file", "", "operator-owned private Cloudflare API token file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || (*yes && *plan) {
		return errors.New("usage: boetticher module media plan|apply|status|teardown [--plan|--yes]")
	}
	var lock *site.OperationLock
	var err error
	if action == "apply" || action == "teardown" {
		lock, err = acquireClientServicesLock()
		if err != nil {
			return err
		}
		defer lock.Release()
	}
	c, err := controllerhost.LoadConfig()
	if err != nil {
		return err
	}
	switch action {
	case "plan":
		return runArrstackPlan(c, "MEDIA plan", out)
	case "status":
		enabled := c.Modules.Media != nil && c.Modules.Media.Enabled
		fmt.Fprintf(out, "MEDIA: %s\nGuest: %s VMID %d address %s\n", map[bool]string{true: "configured", false: "not configured"}[enabled], arrstack.GuestName, arrstack.GuestVMID, arrstack.GuestAddress)
		if !enabled {
			return errors.New("media capability is not configured")
		}
		sc, err := loadClientServiceContext()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		mediaGiB := sc.Config.Modules.Normalize().Media.MediaGiB
		port := arrstackPeerPort(c.Modules)
		runtime, err := arrstack.ReadStatusWithConfigAndMonitoring(ctx, sc.Host, port, *c.Modules.Media, observability.Enabled(c.Modules), mediaGiB)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Guest runtime: exists=%v running=%v agent=%v docker=%v app=%v (%s)\n", runtime.Exists, runtime.Running, runtime.AgentReady, runtime.DockerReady, runtime.AppReady, runtime.Detail)
		provider, err := requireClientProvider(ctx, sc.Site, sc.Desired, sc.Host)
		if err != nil {
			return err
		}
		defer provider.Close()
		state, err := firewallmodule.ServiceStateFromModules(sc.Site, c.Modules)
		if err != nil {
			return err
		}
		if _, err := verifyVPN(ctx, provider, sc, c.Modules, state, out); err != nil {
			fmt.Fprintln(out, "VPN: UNHEALTHY (protected client remains blocked)")
			return err
		}
		fmt.Fprintln(out, "VPN: HEALTHY")
		if !runtime.AppReady {
			return errors.New("arrstack application is not healthy")
		}
		return nil
	case "test":
		if c.Modules.Media == nil || !c.Modules.Media.Enabled {
			return errors.New("media capability is not configured")
		}
		if len(args) != 1 || args[0] != "--yes" {
			return errors.New("module media test requires --yes")
		}
		sc, err := loadClientServiceContext()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		mediaGiB := sc.Config.Modules.Normalize().Media.MediaGiB
		runtime, err := arrstack.ReadStatusWithConfigAndMonitoring(ctx, sc.Host, arrstackPeerPort(c.Modules), *c.Modules.Media, observability.Enabled(c.Modules), mediaGiB)
		if err != nil {
			return err
		}
		if !runtime.AppReady {
			return fmt.Errorf("arrstack runtime test failed: %s", runtime.Detail)
		}
		fmt.Fprintln(out, "MEDIA local runtime: PASS (QEMU guest agent, Docker, adapter and state)")
		fmt.Fprintln(out, "Remote ingress, peer forwarding, packet and physical acceptance: NOT TESTED")
		return nil
	case "apply":
		if *plan {
			return runArrstackPlan(c, "MEDIA apply plan", out)
		}
		return runArrstackApply(c, *yes, *cloudflareTokenFile, input, out)
	case "teardown":
		if *plan {
			fmt.Fprintf(out, "MEDIA teardown plan: stop VMID %d, withdraw aliases and peer forward; retain media, reservation and VPN client\n", arrstack.GuestVMID)
			return nil
		}
		return runArrstackTeardown(c, *yes, input, out)
	default:
		return fmt.Errorf("module capability %q does not implement action %q", "arrstack", action)
	}
}

const mediaApplyTransportTimeout = 21 * time.Minute

func runArrstackApply(current controllerhost.LabConfig, yes bool, cloudflareTokenFile string, input io.Reader, out io.Writer) error {
	sc, err := loadClientServiceContext()
	if err != nil {
		return err
	}
	proposed, changes, err := prepareArrstackModules(current.Modules)
	if err != nil {
		return err
	}
	changed := len(changes) > 0
	mediaGiB := proposed.Normalize().Media.MediaGiB
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	sc.Host.Transport.Timeout = mediaApplyTransportTimeout
	provider, err := requireClientProvider(ctx, sc.Site, sc.Desired, sc.Host)
	if err != nil {
		return err
	}
	defer provider.Close()
	state, err := firewallmodule.ServiceStateFromModules(sc.Site, proposed)
	if err != nil {
		return err
	}
	facts, err := inspectArrstackApply(ctx, sc, provider, state, proposed, changes)
	if err != nil {
		return err
	}
	port := arrstackPeerPort(proposed)
	if facts.NoOp() {
		if _, err := verifyVPN(ctx, provider, sc, proposed, state, out); err != nil {
			return fmt.Errorf("VPN must be healthy before arrstack apply: %w", err)
		}
		if err := reconcileMediaMonitoring(ctx, sc, proposed, out); err != nil {
			return err
		}
		fmt.Fprintln(out, "MEDIA: already applied and verified")
		return nil
	}
	renderArrstackApplyPlan(out, "MEDIA apply", facts)
	if !yes {
		if input == nil {
			return errors.New("module arrstack apply requires --yes or confirmation")
		}
		ok, promptErr := promptYesNo(bufio.NewReader(input), out, "Enable arrstack and reconcile the Host VM? [y/N]: ", false)
		if promptErr != nil || !ok {
			return errors.New("module arrstack apply cancelled")
		}
	}
	var cloudflareToken []byte
	if cloudflareTokenFile != "" {
		cloudflareToken, err = readArrstackPrivateToken(cloudflareTokenFile)
		if err != nil {
			return err
		}
		defer wipeArrstackPrivateToken(cloudflareToken)
	}
	if !facts.Guest.Exists && len(cloudflareToken) == 0 {
		return errors.New("arrstack first install requires --cloudflare-token-file")
	}
	if changed {
		current.Modules = proposed
		if err := controllerhost.SaveConfig(current); err != nil {
			return err
		}
	}
	if _, _, err := reconcileClientServices(ctx, provider, sc, proposed); err != nil {
		return fmt.Errorf("reconcile DNS/DHCP/VPN prerequisites: %w", err)
	}
	if _, err := verifyVPN(ctx, provider, sc, proposed, state, out); err != nil {
		return fmt.Errorf("VPN must be healthy before arrstack guest start: %w", err)
	}
	if err := arrstack.EnsureGuestWithMedia(ctx, sc.Host, mediaGiB); err != nil {
		return err
	}
	if err := arrstack.Start(ctx, sc.Host, mediaGiB); err != nil {
		return err
	}
	if len(cloudflareToken) == 0 {
		retained, credentialErr := arrstack.HasRetainedCaddyCredential(ctx, sc.Host)
		if credentialErr != nil {
			return credentialErr
		}
		if !retained {
			return errors.New("arrstack runtime repair requires --cloudflare-token-file because no retained private Caddy credential is available")
		}
	}
	monitoring := proposed.Observability != nil && clientservices.Enabled(proposed.Observability.Enabled)
	if err := arrstack.InstallRuntimeWithConfigAndMonitoring(ctx, sc.Host, port, cloudflareToken, *proposed.Media, monitoring, mediaGiB); err != nil {
		return err
	}
	runtime, err := arrstack.ReadStatusWithConfigAndMonitoring(ctx, sc.Host, port, *proposed.Media, observability.Enabled(proposed), mediaGiB)
	if err != nil {
		return err
	}
	if !runtime.AppReady {
		return fmt.Errorf("arrstack apply verification failed: %s", runtime.Detail)
	}
	if err := reconcileMediaMonitoring(ctx, sc, proposed, out); err != nil {
		return err
	}
	fmt.Fprintln(out, "MEDIA: applied and verified (guest, Docker and headless application)")
	return nil
}

func reconcileMediaMonitoring(ctx context.Context, sc clientServiceContext, modules clientservices.Modules, out io.Writer) error {
	if !observability.Enabled(modules) {
		return nil
	}
	store := observability.SecretStore{}
	secrets, err := store.Load()
	if err != nil {
		return fmt.Errorf("load observability secrets for media monitoring: %w", err)
	}
	payloadRoot, err := observabilityPayloadRoot()
	if err != nil {
		return fmt.Errorf("resolve observability payload for media monitoring: %w", err)
	}
	payloadDigest, err := observability.PayloadDigest(payloadRoot)
	if err != nil {
		return fmt.Errorf("digest observability payload for media monitoring: %w", err)
	}
	controllerAddress, err := observability.ControllerCollectionAddress(sc.Config)
	if err != nil {
		return err
	}
	collection, err := observability.CollectionConfigForLab(sc.Config, controllerAddress)
	if err != nil {
		return err
	}
	digest, err := observabilityDigest(modules, secrets, payloadDigest, collection)
	if err != nil {
		return fmt.Errorf("derive observability configuration digest for media monitoring: %w", err)
	}
	binding, _ := observability.BindingFor("observability")
	domain := modules.Observability.PublicDomain
	client := observability.HostClient{Transport: sc.Host.Transport, LocalRunner: observabilityLocalRunner()}
	if err := client.ReconcileGuestWithTLS(ctx, binding, payloadRoot, modules, secrets, domain, digest, collection); err != nil {
		return fmt.Errorf("reconcile observability for media monitoring: %w", err)
	}
	fmt.Fprintln(out, "MEDIA monitoring: reconciled (collection, Gatus and Grafana)")
	return nil
}

func arrstackPeerPort(modules clientservices.Modules) int {
	if modules.VPN != nil {
		for _, forward := range modules.VPN.Forwards {
			if forward.Name == "media-qbittorrent" {
				return forward.Port
			}
		}
	}
	return arrstack.QBitTorrentPort
}

func readArrstackPrivateToken(path string) ([]byte, error) {
	if path == "" || path == "/dev/stdin" {
		return nil, errors.New("Cloudflare token path must be an operator-owned private file")
	}
	if err := pathguard.ValidateNoSymlinkComponents(path); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("Cloudflare token path is not a private regular file")
	}
	data, err := pathguard.ReadFileLimited(path, 16<<10)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		wipeArrstackPrivateToken(data)
		return nil, errors.New("Cloudflare token file is empty")
	}
	token := append([]byte(nil), trimmed...)
	wipeArrstackPrivateToken(data)
	return token, nil
}

func wipeArrstackPrivateToken(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func runArrstackTeardown(current controllerhost.LabConfig, yes bool, input io.Reader, out io.Writer) error {
	if current.Modules.Media == nil || !current.Modules.Media.Enabled {
		fmt.Fprintln(out, "MEDIA teardown: already disabled; reservation and VPN client retained")
		return nil
	}
	proposed := current.Modules.Clone()
	proposed.Media.Enabled = false
	if proposed.VPN != nil {
		forwards := proposed.VPN.Forwards[:0]
		for _, forward := range proposed.VPN.Forwards {
			if forward.Name != "media-qbittorrent" {
				forwards = append(forwards, forward)
			}
		}
		proposed.VPN.Forwards = forwards
	}
	if !yes {
		if input == nil {
			return errors.New("module arrstack teardown requires --yes or confirmation")
		}
		ok, err := promptYesNo(bufio.NewReader(input), out, "Disable arrstack and stop the Host VM? [y/N]: ", false)
		if err != nil || !ok {
			return errors.New("module arrstack teardown cancelled")
		}
	}
	sc, err := loadClientServiceContext()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	provider, err := requireClientProvider(ctx, sc.Site, sc.Desired, sc.Host)
	if err != nil {
		return err
	}
	defer provider.Close()
	if err := controllerhost.SaveConfig(func() controllerhost.LabConfig { current.Modules = proposed; return current }()); err != nil {
		return err
	}
	if _, _, err := reconcileClientServices(ctx, provider, sc, proposed); err != nil {
		return fmt.Errorf("arrstack intent saved but provider reconciliation failed: %w", err)
	}
	mediaGiB := proposed.Normalize().Media.MediaGiB
	if err := arrstack.Teardown(ctx, sc.Host, mediaGiB); err != nil {
		return fmt.Errorf("arrstack intent and provider reconciled but VM teardown failed: %w", err)
	}
	fmt.Fprintln(out, "MEDIA: disabled and VM stopped; media, reservation and VPN client retained")
	return nil
}

// arrstackIntentChange is one lab.yml field apply would save.
type arrstackIntentChange struct {
	Field, Before, After string
}

func (c arrstackIntentChange) String() string {
	return fmt.Sprintf("%s: %s -> %s", c.Field, c.Before, c.After)
}

// arrstackApplyFacts is the read-only evidence apply and plan share to decide
// between a verified no-op and the ordered reconciliation steps.
type arrstackApplyFacts struct {
	Changes       []arrstackIntentChange
	ProviderDrift error
	Guest         arrstack.GuestFacts
	Runtime       arrstack.RuntimeStatus
	RuntimeErr    error
	AdapterAgrees bool
	// VPNErr is observed only by plan, and only when nothing else needs
	// reconciliation; apply checks VPN health itself before the guest starts.
	VPNErr     error
	Monitoring bool
	MediaGiB   int
}

// NoOp reports whether apply may skip approval: desired intent, provider and
// guest runtime all agree.
func (f arrstackApplyFacts) NoOp() bool {
	return len(f.Changes) == 0 && f.ProviderDrift == nil && f.RuntimeErr == nil && f.Runtime.AppReady && f.AdapterAgrees
}

// inspectArrstackApply gathers the read-only facts apply acts on. It never
// mutates intent, provider, or guest.
func inspectArrstackApply(ctx context.Context, sc clientServiceContext, provider *openwrt.Client, state firewallmodule.ServiceState, proposed clientservices.Modules, changes []arrstackIntentChange) (arrstackApplyFacts, error) {
	mediaGiB := proposed.Normalize().Media.MediaGiB
	facts := arrstackApplyFacts{Changes: changes, Monitoring: observability.Enabled(proposed), MediaGiB: mediaGiB}
	verifyErr := verifyClientServices(ctx, provider, state, "arrstack")
	if verifyErr != nil && !strings.Contains(verifyErr.Error(), "not at the desired state") {
		return facts, fmt.Errorf("verify DNS/DHCP/VPN prerequisites: %w", verifyErr)
	}
	facts.ProviderDrift = verifyErr
	guest, err := arrstack.InspectGuest(ctx, sc.Host, mediaGiB)
	if err != nil {
		return facts, err
	}
	facts.Guest = guest
	facts.Runtime, facts.RuntimeErr = arrstack.ReadStatusWithConfigAndMonitoring(ctx, sc.Host, arrstackPeerPort(proposed), *proposed.Media, facts.Monitoring, mediaGiB)
	if facts.RuntimeErr != nil && len(changes) == 0 && verifyErr == nil {
		return facts, facts.RuntimeErr
	}
	if len(changes) == 0 && verifyErr == nil && facts.RuntimeErr == nil && facts.Runtime.AppReady {
		facts.AdapterAgrees, err = arrstack.AdapterBytesAgree(ctx, sc.Host)
		if err != nil {
			return facts, fmt.Errorf("verify arrstack adapter bytes: %w", err)
		}
	}
	return facts, nil
}

// runArrstackPlan is the read-only preview shared by plan and apply --plan.
func runArrstackPlan(c controllerhost.LabConfig, title string, out io.Writer) error {
	proposed, changes, err := prepareArrstackModules(c.Modules)
	if err != nil {
		return err
	}
	sc, err := loadClientServiceContext()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	provider, err := requireClientProvider(ctx, sc.Site, sc.Desired, sc.Host)
	if err != nil {
		return err
	}
	defer provider.Close()
	state, err := firewallmodule.ServiceStateFromModules(sc.Site, proposed)
	if err != nil {
		return err
	}
	facts, err := inspectArrstackApply(ctx, sc, provider, state, proposed, changes)
	if err != nil {
		return err
	}
	if len(changes) == 0 && facts.ProviderDrift == nil {
		_, facts.VPNErr = verifyVPN(ctx, provider, sc, proposed, state, io.Discard)
	}
	renderArrstackApplyPlan(out, title, facts)
	fmt.Fprintln(out, "  No mutation or confirmation prompt")
	return nil
}

// renderArrstackApplyPlan lists each intent change and each ordered step apply
// would take, derived only from read-only facts.
func renderArrstackApplyPlan(out io.Writer, title string, f arrstackApplyFacts) {
	guestState := "absent"
	if f.Guest.Exists && f.Guest.Running {
		guestState = "running"
	} else if f.Guest.Exists {
		guestState = "stopped"
	}
	fmt.Fprintf(out, "%s\n  Guest: %s VMID %d address %s (%s)\n", title, arrstack.GuestName, arrstack.GuestVMID, arrstack.GuestAddress, guestState)
	if len(f.Changes) == 0 {
		fmt.Fprintln(out, "  Intent: no change")
	} else {
		fmt.Fprintln(out, "  Intent: save lab.yml changes")
		for _, change := range f.Changes {
			fmt.Fprintf(out, "    %s\n", change)
		}
	}
	if f.ProviderDrift != nil {
		fmt.Fprintf(out, "  Provider: DNS/DHCP/VPN prerequisites differ (%v)\n", f.ProviderDrift)
	} else {
		fmt.Fprintln(out, "  Provider: DNS/DHCP/VPN prerequisites at desired state")
	}
	switch {
	case f.RuntimeErr != nil:
		fmt.Fprintf(out, "  Runtime: not determined (%v)\n", f.RuntimeErr)
	case f.Runtime.AppReady && !f.AdapterAgrees && len(f.Changes) == 0 && f.ProviderDrift == nil:
		fmt.Fprintln(out, "  Runtime: application ready; installed adapter differs from this release")
	default:
		fmt.Fprintf(out, "  Runtime: %s\n", f.Runtime.Detail)
	}
	if f.NoOp() {
		if f.VPNErr != nil {
			fmt.Fprintf(out, "  VPN: unhealthy (%v); apply will refuse until it is healthy\n", f.VPNErr)
		}
		fmt.Fprintln(out, "  Apply: no change; intent, provider, guest and application already agree")
		if f.Monitoring {
			fmt.Fprintln(out, "    - reconcile media monitoring (observability enabled)")
		}
		return
	}
	fmt.Fprintln(out, "  Apply will:")
	if len(f.Changes) > 0 {
		fmt.Fprintln(out, "    - save the lab.yml intent changes above")
	}
	if len(f.Changes) > 0 || f.ProviderDrift != nil {
		fmt.Fprintln(out, "    - reconcile DNS/DHCP/VPN prerequisites on the firewall provider")
	}
	fmt.Fprintln(out, "    - require a healthy VPN handshake before the guest starts")
	switch {
	case !f.Guest.Exists:
		fmt.Fprintf(out, "    - create VM %d from the pinned image with a %dGiB media disk (requires --cloudflare-token-file)\n", arrstack.GuestVMID, f.MediaGiB)
		fmt.Fprintf(out, "    - start VM %d and wait for the QEMU guest agent\n", arrstack.GuestVMID)
	case !f.Guest.Running:
		fmt.Fprintf(out, "    - start stopped VM %d and wait for the QEMU guest agent\n", arrstack.GuestVMID)
	default:
		fmt.Fprintf(out, "    - wait for the QEMU guest agent on running VM %d\n", arrstack.GuestVMID)
	}
	if f.Guest.Exists {
		fmt.Fprintln(out, "    - redeploy the Docker application, adapter and policy (requires --cloudflare-token-file unless a retained private Caddy credential is present)")
	} else {
		fmt.Fprintln(out, "    - deploy the Docker application, adapter and policy")
	}
	fmt.Fprintln(out, "    - verify guest agent, Docker and application health")
	if f.Monitoring {
		fmt.Fprintln(out, "    - reconcile media monitoring (observability enabled)")
	}
}

// prepareArrstackModules derives the media intent apply would save and lists
// each field that differs from the saved intent. Defaults that Normalize
// materialises and the unpersisted Arrstack alias are not changes; comparing
// against them made every plan report changed=yes.
func prepareArrstackModules(current clientservices.Modules) (clientservices.Modules, []arrstackIntentChange, error) {
	proposed := current.Clone().Normalize()
	if proposed.DNS == nil || !clientservices.Enabled(proposed.DNS.Enabled) || proposed.DHCP == nil || !clientservices.Enabled(proposed.DHCP.Enabled) || proposed.VPN == nil || !clientservices.Enabled(proposed.VPN.Enabled) {
		return clientservices.Modules{}, nil, errors.New("arrstack requires enabled DNS, DHCP, and VPN intent")
	}
	if proposed.Media == nil {
		return clientservices.Modules{}, nil, errors.New("modules.media.application_domain and aliases must be configured before enabling media")
	}
	var changes []arrstackIntentChange
	if !proposed.Media.Enabled {
		changes = append(changes, arrstackIntentChange{"modules.media.enabled", "false", "true"})
		proposed.Media.Enabled = true
	}
	proposed.Arrstack = proposed.Media
	r := arrstack.Reservation()
	found := false
	for _, item := range proposed.DHCP.Reservations {
		if item == r {
			found = true
			continue
		}
		if strings.EqualFold(item.Name, r.Name) || strings.EqualFold(item.MAC, r.MAC) || item.Address == r.Address {
			return clientservices.Modules{}, nil, errors.New("arrstack reservation conflicts with existing reservation")
		}
	}
	if !found {
		proposed.DHCP.Reservations = append(proposed.DHCP.Reservations, r)
		changes = append(changes, arrstackIntentChange{"modules.dhcp.reservations[" + r.Name + "]", "absent", fmt.Sprintf("zone %s mac %s address %s", r.Zone, r.MAC, r.Address)})
	}
	seen := false
	for _, client := range proposed.VPN.Clients {
		if client == arrstack.GuestName {
			seen = true
		}
	}
	if !seen {
		proposed.VPN.Clients = append(proposed.VPN.Clients, arrstack.GuestName)
		changes = append(changes, arrstackIntentChange{"modules.vpn.clients[" + arrstack.GuestName + "]", "absent", "present"})
	}
	forward := arrstack.VPNForward()
	describe := func(f clientservices.VPNForward) string {
		return fmt.Sprintf("reservation %s protocols %s port %d", f.Reservation, strings.Join(f.Protocols, ","), f.Port)
	}
	seen = false
	for i := range proposed.VPN.Forwards {
		existing := proposed.VPN.Forwards[i]
		if existing.Name != forward.Name {
			continue
		}
		if existing.Reservation != forward.Reservation || len(existing.Protocols) != 2 {
			return clientservices.Modules{}, nil, errors.New("arrstack peer forward is conflicting")
		}
		if existing.Port == 443 || existing.Port == 8080 {
			return clientservices.Modules{}, nil, errors.New("arrstack peer forward must not expose Caddy or qBittorrent web UI ports")
		}
		forward.Port = existing.Port
		if !reflect.DeepEqual(existing.Protocols, forward.Protocols) {
			changes = append(changes, arrstackIntentChange{"modules.vpn.forwards[" + forward.Name + "]", describe(existing), describe(forward)})
		}
		proposed.VPN.Forwards[i] = forward
		seen = true
	}
	if !seen {
		proposed.VPN.Forwards = append(proposed.VPN.Forwards, forward)
		changes = append(changes, arrstackIntentChange{"modules.vpn.forwards[" + forward.Name + "]", "absent", describe(forward)})
	}
	if err := clientservices.Validate(proposed, model.NewSite("lab", "controller-local", model.GatewayModeManaged)); err != nil {
		return clientservices.Modules{}, nil, err
	}
	return proposed, changes, nil
}
