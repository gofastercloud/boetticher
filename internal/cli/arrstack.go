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
		proposed, changed, err := prepareArrstackModules(c.Modules)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "MEDIA plan\n  Guest: %s VMID %d address %s\n  Configuration: %s\n  No mutation or confirmation prompt\n", arrstack.GuestName, arrstack.GuestVMID, arrstack.GuestAddress, yesNo(changed))
		_ = proposed
		return nil
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
		runtime, err := arrstack.ReadStatusWithConfig(ctx, sc.Host, port, *c.Modules.Media, mediaGiB)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Guest runtime: exists=%v running=%v agent=%v docker=%v app=%v (%s)\n", runtime.Exists, runtime.Running, runtime.AgentReady, runtime.DockerReady, runtime.AppReady, runtime.Detail)
		provider, err := requireClientProvider(ctx, sc.Site, sc.Desired, sc.Host)
		if err != nil {
			return err
		}
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
		runtime, err := arrstack.ReadStatusWithConfig(ctx, sc.Host, arrstackPeerPort(c.Modules), *c.Modules.Media, mediaGiB)
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
			proposed, changed, err := prepareArrstackModules(c.Modules)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "MEDIA apply plan: changed=%s guest VMID %d media=%dGiB; protected VPN prerequisites inspected; no mutation\n", yesNo(changed), arrstack.GuestVMID, proposed.Media.MediaGiB)
			return nil
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
	proposed, changed, err := prepareArrstackModules(current.Modules)
	if err != nil {
		return err
	}
	mediaGiB := proposed.Normalize().Media.MediaGiB
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	sc.Host.Transport.Timeout = mediaApplyTransportTimeout
	provider, err := requireClientProvider(ctx, sc.Site, sc.Desired, sc.Host)
	if err != nil {
		return err
	}
	state, err := firewallmodule.ServiceStateFromModules(sc.Site, proposed)
	if err != nil {
		return err
	}
	verifyErr := verifyClientServices(ctx, provider, state, "arrstack")
	if verifyErr != nil && !strings.Contains(verifyErr.Error(), "not at the desired state") {
		return fmt.Errorf("verify DNS/DHCP/VPN prerequisites: %w", verifyErr)
	}
	port := arrstackPeerPort(proposed)
	guestBefore, err := arrstack.InspectGuest(ctx, sc.Host, mediaGiB)
	if err != nil {
		return err
	}
	runtime, runtimeErr := arrstack.ReadStatusWithConfig(ctx, sc.Host, port, *proposed.Media, mediaGiB)
	if runtimeErr != nil && !changed && verifyErr == nil {
		return runtimeErr
	}
	adapterAgrees := false
	if !changed && verifyErr == nil && runtimeErr == nil && runtime.AppReady {
		adapterAgrees, err = arrstack.AdapterBytesAgree(ctx, sc.Host)
		if err != nil {
			return fmt.Errorf("verify arrstack adapter bytes: %w", err)
		}
		if adapterAgrees {
			if _, err := verifyVPN(ctx, provider, sc, proposed, state, out); err != nil {
				return fmt.Errorf("VPN must be healthy before arrstack apply: %w", err)
			}
			if err := reconcileMediaMonitoring(ctx, sc, proposed, out); err != nil {
				return err
			}
			fmt.Fprintln(out, "MEDIA: already applied and verified")
			return nil
		}
	}
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
	if !guestBefore.Exists && len(cloudflareToken) == 0 {
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
	runtime, err = arrstack.ReadStatusWithConfig(ctx, sc.Host, port, *proposed.Media, mediaGiB)
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

func prepareArrstackModules(current clientservices.Modules) (clientservices.Modules, bool, error) {
	proposed := current.Clone().Normalize()
	if proposed.DNS == nil || !clientservices.Enabled(proposed.DNS.Enabled) || proposed.DHCP == nil || !clientservices.Enabled(proposed.DHCP.Enabled) || proposed.VPN == nil || !clientservices.Enabled(proposed.VPN.Enabled) {
		return clientservices.Modules{}, false, errors.New("arrstack requires enabled DNS, DHCP, and VPN intent")
	}
	if proposed.Media == nil {
		return clientservices.Modules{}, false, errors.New("modules.media.application_domain and aliases must be configured before enabling media")
	} else {
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
			return clientservices.Modules{}, false, errors.New("arrstack reservation conflicts with existing reservation")
		}
	}
	if !found {
		proposed.DHCP.Reservations = append(proposed.DHCP.Reservations, r)
	}
	seen := false
	for _, client := range proposed.VPN.Clients {
		if client == arrstack.GuestName {
			seen = true
		}
	}
	if !seen {
		proposed.VPN.Clients = append(proposed.VPN.Clients, arrstack.GuestName)
	}
	forward := arrstack.VPNForward()
	seen = false
	for i := range proposed.VPN.Forwards {
		if proposed.VPN.Forwards[i].Name != forward.Name {
			continue
		}
		if proposed.VPN.Forwards[i].Reservation != forward.Reservation || len(proposed.VPN.Forwards[i].Protocols) != 2 {
			return clientservices.Modules{}, false, errors.New("arrstack peer forward is conflicting")
		}
		if proposed.VPN.Forwards[i].Port == 443 || proposed.VPN.Forwards[i].Port == 8080 {
			return clientservices.Modules{}, false, errors.New("arrstack peer forward must not expose Caddy or qBittorrent web UI ports")
		}
		forward.Port = proposed.VPN.Forwards[i].Port
		proposed.VPN.Forwards[i] = forward
		seen = true
	}
	if !seen {
		proposed.VPN.Forwards = append(proposed.VPN.Forwards, forward)
	}
	if err := clientservices.Validate(proposed, model.NewSite("lab", "controller-local", model.GatewayModeManaged)); err != nil {
		return clientservices.Modules{}, false, err
	}
	return proposed, !reflect.DeepEqual(current, proposed), nil
}
