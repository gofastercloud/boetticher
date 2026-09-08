package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/observability"
	"github.com/gofastercloud/boetticher/internal/site"
)

var loadLabConfig = controllerhost.LoadConfig
var saveLabConfig = controllerhost.SaveConfig
var observabilityTransport = func(config controllerhost.LabConfig) (observability.Runner, error) {
	return controllerhost.TransportFor(config)
}
var acquireObservabilityLock = site.AcquireOperationLockAt
var observabilityPayloadRoot = controllerhost.ResolveProxmoxRuntime
var observedControllerIP = observability.ObservedControllerIP
var observabilityLocalRunner = func() observability.LocalRunner { return observability.BoundedLocalRunner{} }

func runObservabilityCapability(capability, action string, args []string, input io.Reader, out, errOut io.Writer) error {
	b, _ := observability.BindingFor("observability")
	if action != "plan" && action != "status" && action != "apply" && action != "teardown" && action != "test" && action != "secrets" {
		return fmt.Errorf("module capability %q does not implement action %q", capability, action)
	}
	if action == "secrets" {
		fs := flag.NewFlagSet("module observability secrets", flag.ContinueOnError)
		fs.SetOutput(errOut)
		yes := fs.Bool("yes", false, "approve secret removal")
		if err := fs.Parse(args); err != nil {
			return err
		}
		return runObservabilitySecrets(fs.Args(), *yes, input, out, errOut)
	}
	fs := flag.NewFlagSet("module "+capability+" "+action, flag.ContinueOnError)
	fs.SetOutput(errOut)
	yes := fs.Bool("yes", false, "approve the intent change")
	planOnly := fs.Bool("plan", false, "show the teardown plan without changing state")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *planOnly && action != "teardown" {
		return errors.New("--plan is only supported for module teardown")
	}
	if action == "test" {
		config, err := loadLabConfig()
		if err != nil {
			return err
		}
		if !observability.Enabled(config.Modules) {
			return errors.New("observability is disabled")
		}
		transport, err := observabilityTransport(config)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := (observability.HostClient{Transport: transport}).VerifyReadiness(ctx, b); err != nil {
			return err
		}
		fmt.Fprintln(out, "Module observability test: PASS (owned guest and local provider endpoints ready)")
		return nil
	}
	if action == "apply" {
		return applyObservability(b, *yes, input, out)
	}
	if action == "teardown" {
		return teardownObservability(b, *yes, *planOnly, input, out)
	}
	config, err := loadLabConfig()
	if err != nil {
		return err
	}
	if action == "status" && !observability.Enabled(config.Modules) {
		desired := "disabled"
		if config.Modules.Observability != nil {
			desired = "disabled"
		} else {
			desired = "unconfigured"
		}
		fmt.Fprintf(out, "Module %s\n  Desired  %s\n  State    %s\n", capability, desired, desired)
		return nil
	}
	transport, err := observabilityTransport(config)
	if err != nil {
		return err
	}
	client := observability.HostClient{Transport: transport}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if action == "plan" {
		return planObservability(ctx, client, b, out)
	}
	state, err := client.GuestStatus(ctx, b)
	if err != nil {
		return err
	}
	services := requiredObservabilityServices(capability, nil)
	serviceStates := make([]string, 0, len(services))
	for _, serviceName := range services {
		svc, serviceErr := client.ServiceStatus(ctx, b, serviceName)
		if serviceErr != nil {
			return serviceErr
		}
		if action == "status" && !serviceHealthy(svc) {
			return fmt.Errorf("module %s service %s unhealthy: %s", capability, serviceName, svc)
		}
		serviceStates = append(serviceStates, serviceName+"="+svc)
		if action == "status" {
			endpoint, endpointErr := client.ProviderHealth(ctx, b, serviceName)
			if endpointErr != nil {
				return fmt.Errorf("module %s provider %s unhealthy: %w", capability, serviceName, endpointErr)
			}
			serviceStates = append(serviceStates, serviceName+"-endpoint="+endpoint)
		}
	}
	if action == "status" && capability == "aiops" {
		runnerState, runnerErr := client.HolmesRunnerStatus(ctx, b)
		if runnerErr != nil {
			return fmt.Errorf("module aiops Holmes runner unavailable: %w", runnerErr)
		}
		serviceStates = append(serviceStates, "holmes-runner="+runnerState)
	}
	fmt.Fprintf(out, "Module %s\n  Desired  %t\n  Guest    %d (%s)\n  Services %s\n", capability, observability.Enabled(config.Modules), b.VMID, state, strings.Join(serviceStates, ", "))
	if action == "plan" {
		if observability.Enabled(config.Modules) {
			fmt.Fprintln(out, "  Change    configured intent and owned runtime inspected; no mutation")
		} else {
			fmt.Fprintln(out, "  Change    capability remains disabled; owned runtime inspected")
		}
	}
	return nil
}

func serviceHealthy(value string) bool {
	fields := strings.Fields(strings.ToLower(value))
	return len(fields) == 1 && fields[0] == "active" || len(fields) >= 2 && fields[0] == "active" && fields[1] == "running"
}

func planObservability(ctx context.Context, client observability.HostClient, b observability.Binding, out io.Writer) error {
	observation, err := client.ObserveGuest(ctx, b)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Module observability plan\n  Guest    %d (%s)\n", b.VMID, observation.State)
	switch observation.State {
	case "absent":
		fmt.Fprintf(out, "  Change   Create unprivileged LXC on vmbr1 VLAN %d with %dMiB, metrics 24GiB, logs 24GiB, and state 4GiB retained data\n", b.VLAN, b.MemoryMiB)
	case "owned":
		service, serviceErr := client.ServiceStatus(ctx, b, "victoriametrics.service")
		if serviceErr == nil && serviceHealthy(service) {
			fmt.Fprintln(out, "  Change   Preserve healthy owned runtime")
		} else {
			fmt.Fprintln(out, "  Change   Reconcile owned runtime and provider")
		}
	case "conflict":
		fmt.Fprintf(out, "  Change   Conflict: %s\n", observation.Detail)
	}
	return nil
}

func applyObservability(b observability.Binding, yes bool, input io.Reader, out io.Writer) error {
	lock, err := acquireObservabilityLock(controllerhost.ClientServicesLockPath)
	if err != nil {
		return err
	}
	defer lock.Release()
	config, err := loadLabConfig()
	if err != nil {
		return err
	}
	transport, err := observabilityApplyTransport(config)
	if err != nil {
		return err
	}
	client := observability.HostClient{Transport: transport, LocalRunner: observabilityLocalRunner()}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	observation, err := client.ObserveGuest(ctx, b)
	if err != nil {
		return err
	}
	if observation.State == "conflict" {
		return fmt.Errorf("module observability apply refused: %s", observation.Detail)
	}
	domain := model.DefaultDomain
	if config.Network != nil && config.Network.Domain != "" {
		domain = config.Network.Domain
	}
	store := observability.SecretStore{}
	secrets, secretErr := store.Load()
	if secretErr != nil {
		return secretErr
	}
	payloadRoot, payloadErr := observabilityPayloadRoot()
	if payloadErr != nil {
		return payloadErr
	}
	payloadDigest, payloadErr := observability.PayloadDigest(payloadRoot)
	if payloadErr != nil {
		return payloadErr
	}
	controllerAddress, controllerAddressErr := observability.ControllerCollectionAddress(config)
	if controllerAddressErr != nil {
		return controllerAddressErr
	}
	collection, collectionErr := observability.CollectionConfigForLab(config, controllerAddress)
	if collectionErr != nil {
		return collectionErr
	}
	if observability.Enabled(config.Modules) && observation.State == "owned" {
		desiredDigest, digestErr := observabilityDigest(config.Modules, secrets, payloadDigest, collection)
		servicesHealthy := true
		for _, serviceName := range observability.Services() {
			service, serviceErr := client.ServiceStatus(ctx, b, serviceName)
			if serviceErr != nil || !serviceHealthy(service) {
				servicesHealthy = false
				break
			}
		}
		runtimeDigest, runtimeErr := client.RuntimeDigest(ctx, b)
		if servicesHealthy && digestErr == nil && runtimeErr == nil && runtimeDigest == desiredDigest {
			fmt.Fprintln(out, "Module observability: PASS (already configured and healthy)")
			return nil
		}
	}
	if !yes && !affirm(input, out, "Apply the observability guest and provider? [y/N] ") {
		return errors.New("module change cancelled")
	}
	setObservabilityEnabled(&config.Modules, true)
	if err := saveLabConfig(config); err != nil {
		return err
	}
	if err := reconcileObservabilityDependencies(ctx, config); err != nil {
		return fmt.Errorf("reconcile observability DNS and firewall dependencies: %w", err)
	}
	desiredDigest, err := observabilityDigest(config.Modules, secrets, payloadDigest, collection)
	if err != nil {
		return err
	}
	if err := client.ReconcileGuestWithTLS(ctx, b, payloadRoot, config.Modules, secrets, domain, desiredDigest, collection); err != nil {
		return err
	}
	for _, serviceName := range observability.Services() {
		service, serviceErr := client.ServiceStatus(ctx, b, serviceName)
		if serviceErr != nil || !serviceHealthy(service) {
			if serviceErr != nil {
				return fmt.Errorf("module observability provider health verification for %s: %w", serviceName, serviceErr)
			}
			return fmt.Errorf("module observability provider health verification failed for %s: %s", serviceName, service)
		}
	}
	fmt.Fprintln(out, "Module observability: PASS (guest reconciled and provider healthy)")
	return nil
}

func reconcileObservabilityDependencies(ctx context.Context, config controllerhost.LabConfig) error {
	current, desired, host, err := loadFirewallContext()
	if err != nil {
		return err
	}
	provider, err := requireClientProvider(ctx, current, desired, host)
	if err != nil {
		return err
	}
	serviceContext := clientServiceContext{Config: config, Site: current, Desired: desired, Host: host}
	if _, _, err := reconcileClientServices(ctx, provider, serviceContext, config.Modules); err != nil {
		return err
	}
	return nil
}

func observabilityApplyTransport(config controllerhost.LabConfig) (controllerhost.Transport, error) {
	runner, err := observabilityTransport(config)
	if err != nil {
		return controllerhost.Transport{}, err
	}
	transport, ok := runner.(controllerhost.Transport)
	if !ok {
		return controllerhost.Transport{}, errors.New("observability apply transport does not support bounded SSH timeout")
	}
	// Provider downloads and first convergence already have the explicit
	// thirty-minute apply budget below. Keep the short default for bounded
	// status/read paths while allowing this approved mutation to finish.
	transport.Timeout = 30 * time.Minute
	return transport, nil
}

func observabilityDigest(modules clientservices.Modules, secrets map[string][]byte, payloadDigest string, collection observability.CollectionConfig) (string, error) {
	secretDigests := make(map[string]string, len(secrets))
	for name, value := range secrets {
		digest := sha256.Sum256(value)
		secretDigests[name] = hex.EncodeToString(digest[:])
	}
	data, err := json.Marshal(struct {
		Modules       clientservices.Modules         `json:"modules"`
		Secrets       map[string]string              `json:"secrets"`
		PayloadDigest string                         `json:"payload_digest"`
		Collection    observability.CollectionConfig `json:"collection"`
	}{modules.Clone(), secretDigests, payloadDigest, collection})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func requiredObservabilityServices(capability string, monitoring *clientservices.MonitoringConfig) []string {
	_ = monitoring
	switch capability {
	case "logging":
		return []string{"victorialogs.service", "grafana.service"}
	case "monitoring":
		return []string{"victoriametrics.service", "grafana.service"}
	case "statuspage":
		return []string{"gatus.service"}
	case "aiops":
		return []string{"bifrost.service"}
	default:
		return observability.Services()
	}
}

func capabilityConfigured(modules clientservices.Modules, capability string) bool {
	return capability == "observability" && modules.Observability != nil
}

func setObservabilityEnabled(modules *clientservices.Modules, enabled bool) {
	if modules.Observability == nil {
		modules.Observability = &clientservices.ObservabilityConfig{}
	}
	modules.Observability.Enabled = &enabled
}

func affirm(input io.Reader, out io.Writer, prompt string) bool {
	if input == nil {
		return false
	}
	fmt.Fprint(out, prompt)
	var response string
	if _, err := fmt.Fscanln(input, &response); err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(response), "y") || strings.EqualFold(strings.TrimSpace(response), "yes")
}

func teardownObservability(b observability.Binding, yes, planOnly bool, input io.Reader, out io.Writer) error {
	lock, err := acquireObservabilityLock(controllerhost.ClientServicesLockPath)
	if err != nil {
		return err
	}
	defer lock.Release()
	config, err := loadLabConfig()
	if err != nil {
		return err
	}
	transport, err := observabilityTransport(config)
	if err != nil {
		return err
	}
	client := observability.HostClient{Transport: transport, LocalRunner: observabilityLocalRunner()}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	observation, err := client.ObserveGuest(ctx, b)
	if err != nil {
		return err
	}
	if observation.State == "conflict" {
		return fmt.Errorf("module observability teardown refused: %s", observation.Detail)
	}
	fmt.Fprintf(out, "Module observability teardown\n  Guest    %d (%s)\n  Data     metrics/logs/state volumes retained\n", b.VMID, observation.State)
	if planOnly {
		return nil
	}
	if !yes && !affirm(input, out, "Remove the owned observability guest and retain its data? [y/N] ") {
		return errors.New("module teardown cancelled")
	}
	setObservabilityEnabled(&config.Modules, false)
	if err := saveLabConfig(config); err != nil {
		return err
	}
	if err := client.TeardownGuest(ctx, b); err != nil {
		return err
	}
	fmt.Fprintln(out, "Module observability teardown: PASS (data retained)")
	return nil
}
