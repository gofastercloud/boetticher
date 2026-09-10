package observability

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gofastercloud/boetticher/internal/bifrost"
	"github.com/gofastercloud/boetticher/internal/clientservices"
	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/pushover"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

type Volume struct {
	SizeGiB   int
	MountPath string
}

// Binding is deliberately singular: every provider is reconciled in the one
// owned LXC. Component commands are observation-only views of this runtime.
type Binding struct {
	OwnerModule, Hostname, Address string
	VMID, VLAN, MemoryMiB          int
	Volumes                        []Volume
}

var binding = Binding{OwnerModule: "observability", Hostname: "lab-monitor-01", Address: "10.10.10.20", VMID: model.MonitorVMID, VLAN: 10, MemoryMiB: 4096, Volumes: []Volume{{24, "/var/lib/victoriametrics"}, {24, "/var/lib/victorialogs"}, {4, "/var/lib/boetticher/observability"}}}

func BindingFor(capability string) (Binding, bool) {
	if capability != "observability" {
		return Binding{}, false
	}
	return binding, true
}
func Enabled(m clientservices.Modules) bool {
	return m.Observability != nil && clientservices.Enabled(m.Observability.Enabled)
}
func Services() []string {
	return []string{"victorialogs.service", "victoriametrics.service", "grafana.service", "gatus.service", "bifrost.service", "boetticher-incidentd.service", "caddy.service"}
}

func ServicesForModules(modules clientservices.Modules) []string {
	services := []string{"victorialogs.service", "victoriametrics.service", "grafana.service", "gatus.service", "caddy.service"}
	if modules.Observability != nil && clientservices.Enabled(modules.Observability.Enabled) && modules.Observability.Monitoring.Holmes != nil && clientservices.Enabled(modules.Observability.Monitoring.Holmes.Enabled) {
		services = append(services, "bifrost.service", "boetticher-incidentd.service")
	}
	return services
}

type Runner interface {
	Run(context.Context, string) (controllerhost.Result, error)
}
type StdinRunner interface {
	Runner
	RunWithStdin(context.Context, string, io.Reader) (controllerhost.Result, error)
}
type HostClient struct {
	Transport   Runner
	LocalRunner LocalRunner
}

const holmesUnitTimeoutSeconds = 295

const CloudflareCredentialName = "cloudflare-dns-token"

type GuestObservation struct {
	State  string
	Config map[string]string
	Detail string
}

func (c HostClient) ObserveGuest(ctx context.Context, b Binding) (GuestObservation, error) {
	r, err := c.Transport.Run(ctx, fmt.Sprintf("pct config %d", b.VMID))
	if err != nil {
		detail := strings.ToLower(err.Error() + " " + string(r.Stderr))
		if qm, qmErr := c.Transport.Run(ctx, fmt.Sprintf("qm config %d", b.VMID)); qmErr == nil && len(qm.Stdout) > 0 {
			return GuestObservation{State: "conflict", Detail: "VMID is occupied by a QEMU guest"}, nil
		}
		if strings.Contains(detail, "does not exist") || strings.Contains(detail, "no such") {
			return GuestObservation{State: "absent"}, nil
		}
		return GuestObservation{}, err
	}
	config, err := parseConfig(string(r.Stdout))
	if err != nil {
		return GuestObservation{}, err
	}
	if config["hostname"] != b.Hostname || !ownedTags(config["tags"], b.OwnerModule) {
		return GuestObservation{State: "conflict", Config: config, Detail: "existing guest is not Boetticher-owned"}, nil
	}
	if !networkIdentityMatchesVLAN(config["net0"], b.Address, b.VLAN) {
		return GuestObservation{State: "conflict", Config: config, Detail: "existing guest has the wrong bridge, VLAN, or address"}, nil
	}
	return GuestObservation{State: "owned", Config: config}, nil
}

func ownedTags(raw, module string) bool {
	tags := ";" + strings.Trim(raw, ";") + ";"
	return strings.Contains(tags, ";boetticher;") && strings.Contains(tags, ";managed;") && strings.Contains(tags, ";module-"+module+";") && strings.Contains(tags, ";boetticher-module-"+module+";")
}

func (c HostClient) ReconcileGuest(ctx context.Context, b Binding, payloadRoot string, modules clientservices.Modules, secrets map[string][]byte, digest string) error {
	return c.ReconcileGuestWithTLS(ctx, b, payloadRoot, modules, secrets, "", digest, CollectionConfig{})
}

func (c HostClient) ReconcileGuestWithTLS(ctx context.Context, b Binding, payloadRoot string, modules clientservices.Modules, secrets map[string][]byte, domain, digest string, collection CollectionConfig) error {
	observation, err := c.ObserveGuest(ctx, b)
	if err != nil {
		return err
	}
	if observation.State == "conflict" {
		return fmt.Errorf("guest %d conflict: %s", b.VMID, observation.Detail)
	}
	if observation.State == "absent" {
		stager, ok := c.Transport.(StdinRunner)
		if !ok {
			return errors.New("observability payload transport cannot stage the base helper")
		}
		helperPath := payloadRoot + "/controller/proxmox/libexec/boetticher-build-observability-base"
		tempHelperPath := payloadRoot + "/controller/proxmox/libexec/build-temp.py"
		definitionPath := payloadRoot + "/controller/observability/base/debian.yaml"
		helperData, err := os.ReadFile(helperPath)
		if err != nil {
			return fmt.Errorf("read observability base helper: %w", err)
		}
		tempHelperData, err := os.ReadFile(tempHelperPath)
		if err != nil {
			return fmt.Errorf("read build temporary helper: %w", err)
		}
		definitionData, err := os.ReadFile(definitionPath)
		if err != nil {
			return fmt.Errorf("read observability base definition: %w", err)
		}
		inputDigest := baseImageInputDigest(helperData, definitionData)
		hostStageRoot := fmt.Sprintf("/tmp/boetticher-observability-%d-base-stage", b.VMID)
		hostBaseHelper := hostStageRoot + "/build-base"
		hostTempHelper := hostStageRoot + "/build-temp.py"
		hostBaseDefinition := hostStageRoot + "/debian.yaml"
		if err := validateHostStageRoot(hostStageRoot); err != nil {
			return err
		}
		cleaned := false
		defer func() {
			if !cleaned {
				_ = c.cleanupHostStage(hostStageRoot)
			}
		}()
		if _, err := c.Transport.Run(ctx, prepareHostStageCommand(hostStageRoot)); err != nil {
			return fmt.Errorf("prepare Host base staging: %w", err)
		}
		if err := stageHostBytes(ctx, stager, hostBaseHelper, helperData); err != nil {
			return fmt.Errorf("stage observability base helper: %w", err)
		}
		if err := stageHostBytes(ctx, stager, hostTempHelper, tempHelperData); err != nil {
			return fmt.Errorf("stage build temporary helper: %w", err)
		}
		if _, err := c.Transport.Run(ctx, fmt.Sprintf("chmod 0700 %s", shellQuoteValue(hostTempHelper))); err != nil {
			return fmt.Errorf("make build temporary helper executable: %w", err)
		}
		if _, err := c.Transport.Run(ctx, fmt.Sprintf("chmod 0700 %s", shellQuoteValue(hostBaseHelper))); err != nil {
			return fmt.Errorf("make observability base helper executable: %w", err)
		}
		if err := stageHostBytes(ctx, stager, hostBaseDefinition, definitionData); err != nil {
			return fmt.Errorf("stage observability base definition: %w", err)
		}
		mounts := ""
		for index, volume := range b.Volumes {
			mounts += fmt.Sprintf(" --mp%d boetticher-data:%d,mp=%s", index, volume.SizeGiB, shellQuoteValue(volume.MountPath))
		}
		command := fmt.Sprintf("set -eu; test -n \"$(command -v pct)\"; base=/var/lib/vz/template/cache/boetticher-observability-base-0.1.0-amd64.tar.zst; meta=$base.inputs; if [ -f \"$base\" ]; then test -f \"$meta\"; test \"$(stat -c '%%a:%%u:%%g' \"$meta\")\" = 600:0:0; test \"$(sed -n '1p' \"$meta\")\" = %s; test \"$(sed -n '2p' \"$meta\")\" = \"$(sha256sum \"$base\" | awk '{print $1}')\"; else test ! -e \"$meta\"; %s \"$base\" %s; test -f \"$base\"; printf '%%s\\n%%s\\n' %s \"$(sha256sum \"$base\" | awk '{print $1}')\" > \"$meta\"; chmod 0600 \"$meta\"; fi; pvesh get /nodes/$(hostname)/storage/local/content --content vztmpl --output-format json | grep -Fq boetticher-observability-base-0.1.0-amd64.tar.zst; pct create %d local:vztmpl/boetticher-observability-base-0.1.0-amd64.tar.zst --hostname %s --memory %d --cores 2 --swap 0 --unprivileged 1 --onboot 1 --start 0 --tags %s --net0 name=eth0,bridge=vmbr1,tag=%d,firewall=0,ip=%s/24,gw=10.10.10.1,ip6=manual --rootfs boetticher-data:8%s", shellQuoteValue(inputDigest), shellQuoteValue(hostBaseHelper), shellQuoteValue(hostBaseDefinition), shellQuoteValue(inputDigest), b.VMID, shellQuoteValue(b.Hostname), b.MemoryMiB, shellQuoteValue("boetticher;managed;module-"+b.OwnerModule+";boetticher-module-"+b.OwnerModule), b.VLAN, b.Address, mounts)
		if _, err := c.Transport.Run(ctx, command); err != nil {
			return fmt.Errorf("create observability guest: %w", err)
		}
		if err := c.cleanupHostStage(hostStageRoot); err != nil {
			return fmt.Errorf("clean up Host base staging: %w", err)
		}
		cleaned = true
	}
	if _, err := c.Transport.Run(ctx, fmt.Sprintf("set -eu; if ! pct status %d | grep -q 'running'; then pct start %d; fi", b.VMID, b.VMID)); err != nil {
		return fmt.Errorf("start observability guest: %w", err)
	}
	if err := c.pushProviderPayload(ctx, b, payloadRoot, modules, secrets); err != nil {
		return err
	}
	// Bring up the receiver and its TLS ingress before any node agent can send
	// data. VictoriaMetrics starts only after its complete scrape configuration
	// and receiver-only credential are installed below.
	retentionEnvironment := fmt.Sprintf(" BOETTICHER_OBSERVABILITY_METRICS_RETENTION_DAYS=%d BOETTICHER_OBSERVABILITY_LOGS_RETENTION_DAYS=%d", collection.MetricsRetentionDays, collection.LogsRetentionDays)
	pushoverEnvironment := PushoverEnvironment(modules)
	caddyEnvironment := CaddyEnvironment(modules, collection)
	bifrostProbeEnvironment := " BOETTICHER_OBSERVABILITY_BIFROST_PROBE_ENABLED=false"
	if modules.Observability != nil && clientservices.Enabled(modules.Observability.Enabled) && modules.Observability.Monitoring.Holmes != nil && clientservices.Enabled(modules.Observability.Monitoring.Holmes.Enabled) {
		bifrostProbeEnvironment = " BOETTICHER_OBSERVABILITY_BIFROST_PROBE_ENABLED=true"
	}
	providers := []string{"victorialogs", "grafana", "gatus"}
	mediaDashboardEnvironment := " BOETTICHER_OBSERVABILITY_MEDIA_ENABLED=false"
	if modules.Media != nil && modules.Media.Enabled {
		mediaDashboardEnvironment = " BOETTICHER_OBSERVABILITY_MEDIA_ENABLED=true"
	}
	holmesEnvironment := ""
	if modules.Observability != nil && modules.Observability.Monitoring.Holmes != nil {
		h := modules.Observability.Monitoring.Holmes
		retention, queue, rounds, deadline := h.RetentionDays, h.MaxQueue, h.MaxRounds, h.InvestigationDeadlineSecs
		dailyBudget, investigationBudget := h.DailyBudgetUSD, h.InvestigationBudgetUSD
		if retention == 0 {
			retention = 30
		}
		if queue == 0 {
			queue = 100
		}
		if rounds == 0 {
			rounds = 6
		}
		if deadline == 0 {
			deadline = 300
		}
		if dailyBudget == 0 {
			dailyBudget = 2
		}
		if investigationBudget == 0 {
			investigationBudget = 0.25
		}
		holmesEnvironment = fmt.Sprintf(" BOETTICHER_OBSERVABILITY_HOLMES_RETENTION_DAYS=%d BOETTICHER_OBSERVABILITY_HOLMES_MAX_QUEUE=%d BOETTICHER_OBSERVABILITY_HOLMES_MAX_ROUNDS=%d BOETTICHER_OBSERVABILITY_HOLMES_DEADLINE_SECONDS=%d BOETTICHER_OBSERVABILITY_HOLMES_DAILY_BUDGET=%g BOETTICHER_OBSERVABILITY_HOLMES_INVESTIGATION_BUDGET=%g", retention, queue, rounds, deadline, dailyBudget, investigationBudget)
	}
	for _, provider := range providers {
		modelAlias := "operations"
		if modules.Observability != nil && modules.Observability.Monitoring.Holmes != nil && modules.Observability.Monitoring.Holmes.ModelAlias != "" {
			modelAlias = modules.Observability.Monitoring.Holmes.ModelAlias
		}
		installScript := fmt.Sprintf("set -eu; BOETTICHER_OBSERVABILITY_ASSETS=%s BOETTICHER_OBSERVABILITY_CONFIG_DIGEST=%s BOETTICHER_OBSERVABILITY_GATUS_BINARY=/root/gatus BOETTICHER_OBSERVABILITY_BIFROST_BINARY=/root/bifrost BOETTICHER_OBSERVABILITY_INCIDENTD_BINARY=/root/boetticher-incidentd BOETTICHER_OBSERVABILITY_HOLMES_MODEL_ALIAS=%s BOETTICHER_OBSERVABILITY_BIFROST_CONFIG=%s%s%s%s%s%s%s sh /root/boetticher-install-observability-providers %s", shellQuoteValue(fmt.Sprintf("/root/boetticher-observability-assets-%d", b.VMID)), shellQuoteValue(digest), shellQuoteValue(modelAlias), shellQuoteValue(fmt.Sprintf("/root/boetticher-observability-assets-%d/bifrost.config.json", b.VMID)), retentionEnvironment, pushoverEnvironment, caddyEnvironment, bifrostProbeEnvironment, mediaDashboardEnvironment, holmesEnvironment, shellQuoteValue(provider))
		installCommand := fmt.Sprintf("pct exec %d -- sh -c %s", b.VMID, shellQuoteValue(installScript))
		if _, err := c.Transport.Run(ctx, installCommand); err != nil {
			return fmt.Errorf("install %s provider: %w", provider, err)
		}
	}
	if domain != "" {
		if err := c.ReconcileCollection(ctx, b, payloadRoot, modules.Observability.PublicDomain, collection); err != nil {
			return err
		}
		if caddyEnvironment != "" {
			installScript := fmt.Sprintf("set -eu; BOETTICHER_OBSERVABILITY_ASSETS=%s BOETTICHER_OBSERVABILITY_CONFIG_DIGEST=%s BOETTICHER_OBSERVABILITY_CADDY_BINARY=/root/caddy BOETTICHER_OBSERVABILITY_GATUS_BINARY=/root/gatus BOETTICHER_OBSERVABILITY_BIFROST_BINARY=/root/bifrost BOETTICHER_OBSERVABILITY_BIFROST_CONFIG=%s%s%s sh /root/boetticher-install-observability-providers caddy", shellQuoteValue(fmt.Sprintf("/root/boetticher-observability-assets-%d", b.VMID)), shellQuoteValue(digest), shellQuoteValue(fmt.Sprintf("/root/boetticher-observability-assets-%d/bifrost.config.json", b.VMID)), caddyEnvironment, pushoverEnvironment)
			if _, err := c.Transport.Run(ctx, fmt.Sprintf("pct exec %d -- sh -c %s", b.VMID, shellQuoteValue(installScript))); err != nil {
				return fmt.Errorf("install caddy frontend: %w", err)
			}
		}
	}
	providers = []string{"victoriametrics"}
	if modules.Observability != nil && clientservices.Enabled(modules.Observability.Enabled) && modules.Observability.Monitoring.Holmes != nil && clientservices.Enabled(modules.Observability.Monitoring.Holmes.Enabled) {
		providers = append(providers, "bifrost", "holmes", "incidentd")
	}
	for _, provider := range providers {
		holmesRootEnvironment := ""
		if provider == "holmes" {
			holmesRootEnvironment = fmt.Sprintf(" BOETTICHER_OBSERVABILITY_HOLMES_ROOT=%s", shellQuoteValue(fmt.Sprintf("/root/boetticher-observability-assets-%d/holmes", b.VMID)))
		}
		installScript := fmt.Sprintf("set -eu; BOETTICHER_OBSERVABILITY_ASSETS=%s BOETTICHER_OBSERVABILITY_CONFIG_DIGEST=%s BOETTICHER_OBSERVABILITY_GATUS_BINARY=/root/gatus BOETTICHER_OBSERVABILITY_BIFROST_BINARY=/root/bifrost BOETTICHER_OBSERVABILITY_INCIDENTD_BINARY=/root/boetticher-incidentd BOETTICHER_OBSERVABILITY_BIFROST_CONFIG=%s%s%s%s%s%s sh /root/boetticher-install-observability-providers %s", shellQuoteValue(fmt.Sprintf("/root/boetticher-observability-assets-%d", b.VMID)), shellQuoteValue(digest), shellQuoteValue(fmt.Sprintf("/root/boetticher-observability-assets-%d/bifrost.config.json", b.VMID)), retentionEnvironment, holmesRootEnvironment, holmesEnvironment, pushoverEnvironment, mediaDashboardEnvironment, shellQuoteValue(provider))
		if _, err := c.Transport.Run(ctx, fmt.Sprintf("pct exec %d -- sh -c %s", b.VMID, shellQuoteValue(installScript))); err != nil {
			return fmt.Errorf("install %s provider: %w", provider, err)
		}
	}
	// Provider installation rebuilds the base Gatus file. Re-project the full
	// canonical slice afterwards, including an empty slice, so unregistering the
	// final system removes its owned check on the next normal apply.
	gatusConfig, err := c.GatusConfigStatus(ctx)
	if err != nil {
		return fmt.Errorf("read installed Gatus configuration: %w", err)
	}
	if err := c.ReconcileGatus(ctx, []byte(gatusConfig), modules.Systems, modules); err != nil {
		return fmt.Errorf("reconcile Gatus registered-system checks: %w", err)
	}
	state := fmt.Sprintf("install -d -o root -g root -m 0755 /var/lib/boetticher/observability; printf '%%s\\n' %s > /var/lib/boetticher/observability/boetticher-config.digest; chmod 0600 /var/lib/boetticher/observability/boetticher-config.digest", shellQuoteValue(digest))
	if _, err := c.Transport.Run(ctx, fmt.Sprintf("pct exec %d -- sh -c %s", b.VMID, shellQuoteValue(state))); err != nil {
		return fmt.Errorf("record observability runtime digest: %w", err)
	}
	return nil
}

func validDNSName(value string) bool {
	if value == "" || len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") || strings.Contains(value, "..") {
		return false
	}
	for _, part := range strings.Split(value, ".") {
		if part == "" || len(part) > 63 {
			return false
		}
		for _, char := range part {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
				return false
			}
		}
	}
	return true
}

func (c HostClient) pushProviderPayload(ctx context.Context, b Binding, payloadRoot string, modules clientservices.Modules, secrets map[string][]byte) error {
	if strings.TrimSpace(payloadRoot) == "" || !strings.HasPrefix(payloadRoot, "/") || strings.ContainsAny(payloadRoot, "\r\n\x00") {
		return errors.New("installed observability payload path is invalid")
	}
	assetRoot := payloadRoot + "/controller/observability/assets"
	stager, ok := c.Transport.(StdinRunner)
	if !ok {
		return errors.New("observability payload transport cannot stage Controller bytes on Host")
	}
	providerRoot := fmt.Sprintf("/root/boetticher-observability-assets-%d", b.VMID)
	hostRoot := fmt.Sprintf("/tmp/boetticher-observability-%d", b.VMID)
	defer func() { _, _ = c.Transport.Run(ctx, "rm -rf "+shellQuoteValue(hostRoot)) }()
	if _, err := c.Transport.Run(ctx, fmt.Sprintf("install -d -m 0700 %s", shellQuoteValue(hostRoot))); err != nil {
		return fmt.Errorf("prepare Host provider staging: %w", err)
	}
	if _, err := c.Transport.Run(ctx, fmt.Sprintf("pct exec %d -- install -d -m 0755 %s", b.VMID, shellQuoteValue(providerRoot))); err != nil {
		return fmt.Errorf("prepare observability provider payload: %w", err)
	}
	if _, err := c.Transport.Run(ctx, fmt.Sprintf("install -d -m 0700 %s", shellQuoteValue(hostRoot+"/holmes"))); err != nil {
		return fmt.Errorf("prepare Holmes staging: %w", err)
	}
	files := []string{"catalog.json", "victorialogs.service", "victoriametrics.service", "grafana.service", "grafana-datasource.yaml", "grafana-dashboard.yaml", "grafana-overview.json", "grafana-host-resources.json", "grafana-service-logs.json", "grafana-observability-health.json", "grafana-alerting.yaml", "gatus.service", "gatus.config.yaml", "bifrost.service", "boetticher-incidentd.service", "caddy.service"}
	if modules.Media != nil && modules.Media.Enabled {
		files = append(files, "grafana-media.json")
	}
	for _, file := range files {
		local := assetRoot + "/" + file
		hostFile := hostRoot + "/" + file
		remote := providerRoot + "/" + file
		if err := stageHostFile(ctx, stager, local, hostFile); err != nil {
			return fmt.Errorf("stage observability provider asset %s: %w", file, err)
		}
		if _, err := c.Transport.Run(ctx, fmt.Sprintf("pct push %d %s %s", b.VMID, shellQuoteValue(hostFile), shellQuoteValue(remote))); err != nil {
			return fmt.Errorf("upload observability provider asset %s: %w", file, err)
		}
	}
	holmesFiles := []string{"holmes-runner.py", "holmes.yaml", "requirements.lock"}
	for _, file := range holmesFiles {
		local := payloadRoot + "/controller/observability/holmes/" + file
		hostFile := hostRoot + "/holmes/" + file
		remote := providerRoot + "/holmes/" + file
		if err := stageHostFile(ctx, stager, local, hostFile); err != nil {
			return fmt.Errorf("stage Holmes asset %s: %w", file, err)
		}
		if _, err := c.Transport.Run(ctx, fmt.Sprintf("pct exec %d -- install -d -m 0700 %s", b.VMID, shellQuoteValue(providerRoot+"/holmes"))); err != nil {
			return fmt.Errorf("prepare Holmes payload: %w", err)
		}
		if _, err := c.Transport.Run(ctx, fmt.Sprintf("pct push %d %s %s", b.VMID, shellQuoteValue(hostFile), shellQuoteValue(remote))); err != nil {
			return fmt.Errorf("upload Holmes asset %s: %w", file, err)
		}
	}
	helper := payloadRoot + "/controller/proxmox/libexec/boetticher-install-observability-providers"
	hostHelper := hostRoot + "/installer"
	if err := stageHostFile(ctx, stager, helper, hostHelper); err != nil {
		return fmt.Errorf("stage observability provider installer: %w", err)
	}
	if _, err := c.Transport.Run(ctx, fmt.Sprintf("pct push %d %s /root/boetticher-install-observability-providers", b.VMID, shellQuoteValue(hostHelper))); err != nil {
		return fmt.Errorf("upload observability provider installer: %w", err)
	}
	for _, binary := range []struct{ local, host, guest string }{{payloadRoot + "/controller/observability/bin/gatus", hostRoot + "/gatus", "/root/gatus"}, {payloadRoot + "/controller/observability/bin/bifrost", hostRoot + "/bifrost", "/root/bifrost"}, {payloadRoot + "/controller/observability/bin/boetticher-incidentd", hostRoot + "/boetticher-incidentd", "/root/boetticher-incidentd"}, {payloadRoot + "/controller/observability/bin/caddy", hostRoot + "/caddy", "/root/caddy"}} {
		if err := stageHostFile(ctx, stager, binary.local, binary.host); err != nil {
			return err
		}
		if _, err := c.Transport.Run(ctx, fmt.Sprintf("pct push %d %s %s", b.VMID, shellQuoteValue(binary.host), shellQuoteValue(binary.guest))); err != nil {
			return err
		}
		if _, err := c.Transport.Run(ctx, fmt.Sprintf("pct exec %d -- chmod 0755 %s", b.VMID, shellQuoteValue(binary.guest))); err != nil {
			return fmt.Errorf("set executable mode on observability binary: %w", err)
		}
	}
	if modules.Observability != nil && clientservices.Enabled(modules.Observability.Enabled) && modules.Observability.Monitoring.Holmes != nil && clientservices.Enabled(modules.Observability.Monitoring.Holmes.Enabled) {
		config, err := BifrostConfig(modules)
		if err != nil {
			return err
		}
		data, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("encode Bifrost configuration: %w", err)
		}
		if err := stageHostBytes(ctx, stager, hostRoot+"/bifrost.config.json", data); err != nil {
			return err
		}
		if _, err := c.Transport.Run(ctx, fmt.Sprintf("pct push %d %s %s", b.VMID, shellQuoteValue(hostRoot+"/bifrost.config.json"), shellQuoteValue(providerRoot+"/bifrost.config.json"))); err != nil {
			return fmt.Errorf("upload Bifrost configuration: %w", err)
		}
	}
	if _, err := c.Transport.Run(ctx, fmt.Sprintf("pct exec %d -- install -d -m 0700 /var/lib/boetticher/credentials", b.VMID)); err != nil {
		return err
	}
	for _, name := range RequiredSecretNames(modules) {
		value, ok := secrets[name]
		if !ok || len(value) == 0 {
			return fmt.Errorf("required observability secret %q is missing", name)
		}
		filename, filenameErr := CredentialFilename(name)
		if filenameErr != nil {
			return filenameErr
		}
		hostPath := hostRoot + "/credential-" + name
		guestPath := "/var/lib/boetticher/credentials/" + filename
		if err := stageHostBytes(ctx, stager, hostPath, value); err != nil {
			return fmt.Errorf("stage observability secret %s: %w", name, err)
		}
		if _, err := c.Transport.Run(ctx, fmt.Sprintf("pct push %d %s %s", b.VMID, shellQuoteValue(hostPath), shellQuoteValue(guestPath))); err != nil {
			return fmt.Errorf("upload observability secret %s: %w", name, err)
		}
		if _, err := c.Transport.Run(ctx, fmt.Sprintf("pct exec %d -- chmod 0600 %s", b.VMID, shellQuoteValue(guestPath))); err != nil {
			return err
		}
	}
	return nil
}

func stageHostFile(ctx context.Context, stager StdinRunner, local, remote string) error {
	data, err := os.ReadFile(local)
	if err != nil {
		return fmt.Errorf("read Controller payload %s: %w", local, err)
	}
	return stageHostBytes(ctx, stager, remote, data)
}

func baseImageInputDigest(helper, definition []byte) string {
	hash := sha256.New()
	hash.Write([]byte("boetticher-observability-base-input-v1\x00"))
	hash.Write([]byte("helper\x00"))
	hash.Write(helper)
	hash.Write([]byte("\x00definition\x00"))
	hash.Write(definition)
	return hex.EncodeToString(hash.Sum(nil))
}

func validateHostStageRoot(root string) error {
	const prefix = "/tmp/boetticher-observability-"
	if !strings.HasPrefix(root, prefix) || !strings.HasSuffix(root, "-base-stage") {
		return errors.New("observability Host staging path is unsafe")
	}
	vmid := strings.TrimSuffix(strings.TrimPrefix(root, prefix), "-base-stage")
	if vmid == "" {
		return errors.New("observability Host staging path is unsafe")
	}
	for _, char := range vmid {
		if char < '0' || char > '9' {
			return errors.New("observability Host staging path is unsafe")
		}
	}
	if strings.ContainsAny(root, "\r\n\x00'") {
		return errors.New("observability Host staging path is unsafe")
	}
	return nil
}

func prepareHostStageCommand(root string) string {
	quoted := shellQuoteValue(root)
	marker := shellQuoteValue("boetticher-observability-stage-v1")
	return fmt.Sprintf("set -eu; if [ -L %s ]; then exit 1; fi; if [ -e %s ]; then test -d %s; test -f %s/.boetticher-owned; test ! -L %s/.boetticher-owned; test \"$(cat %s/.boetticher-owned)\" = %s; test \"$(stat -c '%%a:%%u:%%g' %s/.boetticher-owned)\" = 600:0:0; else install -d -m 0700 %s; printf '%%s\\n' %s > %s/.boetticher-owned; chmod 0600 %s/.boetticher-owned; fi; test \"$(stat -c '%%a:%%u:%%g' %s)\" = 700:0:0", quoted, quoted, quoted, quoted, quoted, quoted, marker, quoted, quoted, marker, quoted, quoted, quoted)
}

func (c HostClient) cleanupHostStage(root string) error {
	if err := validateHostStageRoot(root); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	quoted := shellQuoteValue(root)
	marker := shellQuoteValue("boetticher-observability-stage-v1")
	command := fmt.Sprintf("set -eu; if [ -d %s ] && [ ! -L %s ] && [ -f %s/.boetticher-owned ] && [ ! -L %s/.boetticher-owned ] && [ \"$(cat %s/.boetticher-owned)\" = %s ]; then rm -rf -- %s; fi", quoted, quoted, quoted, quoted, quoted, marker, quoted)
	_, err := c.Transport.Run(ctx, command)
	return err
}

func stageHostBytes(ctx context.Context, stager StdinRunner, remote string, data []byte) error {
	digest := sha256.Sum256(data)
	expected := hex.EncodeToString(digest[:])
	command := fmt.Sprintf("umask 077; cat > %s; chmod 0600 %s; test \"$(sha256sum %s | awk '{print $1}')\" = %s", shellQuoteValue(remote), shellQuoteValue(remote), shellQuoteValue(remote), expected)
	_, err := stager.RunWithStdin(ctx, command, bytes.NewReader(data))
	return err
}

func shellQuoteValue(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func (c HostClient) TeardownGuest(ctx context.Context, b Binding) error {
	observation, err := c.ObserveGuest(ctx, b)
	if err != nil {
		return err
	}
	if observation.State == "absent" {
		return nil
	}
	if observation.State == "conflict" {
		return fmt.Errorf("guest %d conflict: %s", b.VMID, observation.Detail)
	}
	if observation.State == "owned" {
		if err := c.TeardownCollection(ctx, b); err != nil {
			return err
		}
		// Media collection is a separate QEMU guest and is not included in the
		// observability LXC's default collection target set.
		if _, enrolledTransport := c.Transport.(controllerhost.Transport); enrolledTransport {
			if err := c.TeardownMediaCollection(ctx, b); err != nil {
				return err
			}
		} else if _, enrolledTransport := c.Transport.(*controllerhost.Transport); enrolledTransport {
			if err := c.TeardownMediaCollection(ctx, b); err != nil {
				return err
			}
		}
	}
	for _, service := range Services() {
		if _, err := c.Transport.Run(ctx, fmt.Sprintf("pct exec %d -- systemctl disable --now %s || true", b.VMID, shellQuoteValue(service))); err != nil {
			return fmt.Errorf("stop %s provider: %w", service, err)
		}
	}
	if _, err := c.Transport.Run(ctx, fmt.Sprintf("pct stop %d --timeout 30", b.VMID)); err != nil {
		return fmt.Errorf("stop observability guest: %w", err)
	}
	// V1 retains the stopped, disabled shared runtime and every data mount.
	// Destructive purge is intentionally outside this lifecycle.
	if _, err := c.Transport.Run(ctx, fmt.Sprintf("pct set %d --onboot 0", b.VMID)); err != nil {
		return fmt.Errorf("disable observability runtime: %w", err)
	}
	return nil
}

func (c HostClient) GuestConfig(ctx context.Context, b Binding) (map[string]string, error) {
	r, e := c.Transport.Run(ctx, fmt.Sprintf("pct config %d", b.VMID))
	if e != nil {
		return nil, e
	}
	m, e := parseConfig(string(r.Stdout))
	if e != nil {
		return nil, e
	}
	if m["hostname"] != b.Hostname {
		return nil, fmt.Errorf("guest %d ownership rejected: hostname %q, want %q", b.VMID, m["hostname"], b.Hostname)
	}
	tags := ";" + strings.Trim(m["tags"], ";") + ";"
	if !strings.Contains(tags, ";boetticher;") || !strings.Contains(tags, ";managed;") || !strings.Contains(tags, ";module-"+b.OwnerModule+";") || !strings.Contains(tags, ";boetticher-module-"+b.OwnerModule+";") {
		return nil, fmt.Errorf("guest %d ownership rejected: missing managed observability ownership tags", b.VMID)
	}
	if !networkIdentityMatchesVLAN(m["net0"], b.Address, b.VLAN) && !networkIdentityMatchesVLAN(m["net1"], b.Address, b.VLAN) {
		return nil, fmt.Errorf("guest %d network identity rejected: expected %s", b.VMID, b.Address)
	}
	return m, nil
}

func networkIdentityMatches(raw, address string) bool {
	return networkIdentityMatchesVLAN(raw, address, 0)
}

func networkIdentityMatchesVLAN(raw, address string, vlan int) bool {
	bridge, ip := "", ""
	tag := 0
	for _, field := range strings.Split(raw, ",") {
		p := strings.SplitN(field, "=", 2)
		if len(p) != 2 {
			continue
		}
		switch p[0] {
		case "bridge":
			bridge = p[1]
		case "ip":
			ip = strings.SplitN(p[1], "/", 2)[0]
		case "tag":
			tag, _ = strconv.Atoi(p[1])
		}
	}
	return bridge == "vmbr1" && ip == address && (vlan == 0 || tag == vlan)
}
func (c HostClient) GuestStatus(ctx context.Context, b Binding) (string, error) {
	if _, e := c.GuestConfig(ctx, b); e != nil {
		return "", e
	}
	r, e := c.Transport.Run(ctx, fmt.Sprintf("pct status %d", b.VMID))
	if e != nil {
		return "", e
	}
	return strings.TrimSpace(string(r.Stdout)), nil
}
func (c HostClient) ServiceStatus(ctx context.Context, b Binding, service string) (string, error) {
	if _, e := c.GuestConfig(ctx, b); e != nil {
		return "", e
	}
	r, e := c.Transport.Run(ctx, fmt.Sprintf("pct exec %d -- systemctl is-active %s || true", b.VMID, shellQuoteValue(service)))
	if e != nil {
		return "", e
	}
	return strings.TrimSpace(string(r.Stdout)), nil
}

// ProviderHealth checks the provider's own loopback HTTP health route after
// ownership has been verified. It prevents an active-but-unresponsive unit
// from being reported as healthy by capability status.
func (c HostClient) ProviderHealth(ctx context.Context, b Binding, service string) (string, error) {
	paths := map[string]string{
		"victorialogs.service":         "http://127.0.0.1:9428/health",
		"victoriametrics.service":      "http://127.0.0.1:8428/health",
		"grafana.service":              "http://127.0.0.1:3000/api/health",
		"gatus.service":                "http://127.0.0.1:8080/health",
		"bifrost.service":              "http://127.0.0.1:4000/health",
		"boetticher-incidentd.service": "http://127.0.0.1:8091/health",
		"caddy.service":                "http://unix/config/",
	}
	path, ok := paths[service]
	if !ok {
		return "", fmt.Errorf("unknown observability provider %s", service)
	}
	if _, err := c.GuestConfig(ctx, b); err != nil {
		return "", err
	}
	command := fmt.Sprintf("pct exec %d -- curl --fail --silent --show-error --max-time 5 %s >/dev/null", b.VMID, shellQuoteValue(path))
	if service == "caddy.service" {
		command = fmt.Sprintf("pct exec %d -- curl --fail --silent --show-error --max-time 5 --unix-socket /run/caddy/admin.sock http://unix/config/ >/dev/null", b.VMID)
	}
	if _, err := c.Transport.Run(ctx, command); err != nil {
		return "", fmt.Errorf("%s health endpoint failed: %w", service, err)
	}
	return "healthy", nil
}

// HolmesRunnerStatus verifies only the installed on-demand runner payload. It
// never starts Holmes or contacts Bifrost/model providers.
func (c HostClient) HolmesRunnerStatus(ctx context.Context, b Binding) (string, error) {
	if _, err := c.GuestConfig(ctx, b); err != nil {
		return "", err
	}
	r, err := c.Transport.Run(ctx, fmt.Sprintf("pct exec %d -- sh -c %s", b.VMID, shellQuoteValue("test -x /opt/boetticher/observability/holmes/venv/bin/python; test -f /opt/boetticher/observability/holmes/holmes-runner.py; test -f /etc/boetticher/holmes/config.yaml; printf installed")))
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(string(r.Stdout)) != "installed" {
		return "", errors.New("Holmes runner payload is incomplete")
	}
	return "installed", nil
}

func (c HostClient) RuntimeDigest(ctx context.Context, b Binding) (string, error) {
	r, err := c.Transport.Run(ctx, fmt.Sprintf("pct exec %d -- cat /var/lib/boetticher/observability/boetticher-config.digest", b.VMID))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(r.Stdout)), nil
}

// AskHolmes runs exactly one request in the installed on-demand systemd
// sandbox. The question is streamed over the existing Host transport; no
// credential or transcript is placed in the command line or Controller disk.
func (c HostClient) AskHolmes(ctx context.Context, b Binding, alias string, question io.Reader) (string, error) {
	if !validHolmesAlias(alias) {
		return "", errors.New("Holmes model alias is invalid")
	}
	if question == nil {
		return "", errors.New("Holmes question is required")
	}
	if _, err := c.GuestConfig(ctx, b); err != nil {
		return "", err
	}
	if status, err := c.ServiceStatus(ctx, b, "bifrost.service"); err != nil {
		return "", fmt.Errorf("verify Bifrost readiness: %w", err)
	} else if !serviceHealthy(status) {
		return "", fmt.Errorf("Bifrost service is not active: %s", status)
	}
	stager, ok := c.Transport.(StdinRunner)
	if !ok {
		return "", errors.New("observability transport cannot stream a Holmes question")
	}
	command := fmt.Sprintf("pct exec %d -- systemd-run --pipe --wait --collect --quiet --unit=boetticher-holmes-ask-run --property=Type=oneshot --property=User=holmes --property=Group=holmes --property=Environment=HOME=/var/lib/boetticher/holmes --property=Environment=PATH=/opt/boetticher/observability/holmes/venv/bin:/usr/bin:/bin --property=Environment=PYTHONNOUSERSITE=1 --property=Environment=HOLMES_CONFIGPATH_DIR=/etc/boetticher/holmes --property=NoNewPrivileges=yes --property=CapabilityBoundingSet= --property=ProtectSystem=strict --property=ProtectHome=true --property=PrivateTmp=true --property=PrivateDevices=true --property=RestrictSUIDSGID=true --property='RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' --property=IPAddressDeny=any --property=IPAddressAllow=localhost --property=RuntimeDirectory=boetticher-holmes-ask --property=TimeoutStartSec=%d --property=LoadCredential=holmes-client-token:/var/lib/boetticher/credentials/holmes-client-token.cred /opt/boetticher/observability/holmes/venv/bin/python /opt/boetticher/observability/holmes/holmes-runner.py --model-alias %s", b.VMID, holmesUnitTimeoutSeconds, shellQuoteValue(alias))
	result, err := stager.RunWithStdin(ctx, command, io.LimitReader(question, 32*1024+1))
	if err != nil {
		return "", fmt.Errorf("Holmes ask failed: %w", err)
	}
	answer := strings.TrimSpace(string(result.Stdout))
	if answer == "" {
		return "", errors.New("Holmes returned an empty answer")
	}
	if len(answer) > 64*1024 {
		return "", errors.New("Holmes answer exceeded its bound")
	}
	return answer, nil
}

func validHolmesAlias(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_' || char == '-' || char == '.') {
			return false
		}
	}
	return true
}

func (c HostClient) GuestCertificate(ctx context.Context, b Binding) (string, error) {
	if _, err := c.GuestConfig(ctx, b); err != nil {
		return "", err
	}
	r, err := c.Transport.Run(ctx, fmt.Sprintf("pct exec %d -- cat /var/lib/boetticher/tls/observability.crt.pem", b.VMID))
	if err != nil {
		return "", err
	}
	return string(r.Stdout), nil
}

func (c HostClient) VerifyReadiness(ctx context.Context, b Binding) error {
	return c.VerifyReadinessForModules(ctx, b, clientservices.Modules{})
}

func (c HostClient) VerifyReadinessForModules(ctx context.Context, b Binding, modules clientservices.Modules) error {
	state, err := c.GuestStatus(ctx, b)
	if err != nil {
		return err
	}
	if !strings.Contains(strings.ToLower(state), "running") {
		return fmt.Errorf("observability guest is not running: %s", state)
	}
	for _, service := range ServicesForModules(modules) {
		status, err := c.ServiceStatus(ctx, b, service)
		if err != nil {
			return err
		}
		if !serviceHealthy(status) {
			return fmt.Errorf("observability service %s unhealthy: %s", service, status)
		}
	}
	check := "curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8428/health >/dev/null; curl --fail --silent --show-error --max-time 5 http://127.0.0.1:9428/health >/dev/null; curl --fail --silent --show-error --max-time 5 http://127.0.0.1:3000/api/health >/dev/null; curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8080/health >/dev/null; curl --fail --silent --show-error --max-time 5 --unix-socket /run/caddy/admin.sock http://unix/config/ >/dev/null"
	if modules.Observability != nil && clientservices.Enabled(modules.Observability.Enabled) && modules.Observability.Monitoring.Holmes != nil && clientservices.Enabled(modules.Observability.Monitoring.Holmes.Enabled) {
		check += "; curl --fail --silent --show-error --max-time 5 http://127.0.0.1:4000/health >/dev/null; curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8091/health >/dev/null"
	}
	if _, err := c.Transport.Run(ctx, fmt.Sprintf("pct exec %d -- sh -c %s", b.VMID, shellQuoteValue(check))); err != nil {
		return fmt.Errorf("observability local readiness: %w", err)
	}
	return nil
}

// RotateGrafanaPassword is intentionally separate from reconciliation: it is
// an explicit, confirmed operator mutation. Both credentials travel only over
// stdin to a local guest process; the protected Controller store is updated by
// the caller only after this method verifies the new login.
func (c HostClient) RotateGrafanaPassword(ctx context.Context, b Binding, current, replacement []byte) error {
	if len(current) == 0 || len(replacement) == 0 {
		return errors.New("Grafana password input is empty")
	}
	if _, err := c.GuestConfig(ctx, b); err != nil {
		return err
	}
	stager, ok := c.Transport.(StdinRunner)
	if !ok {
		return errors.New("observability transport cannot stream Grafana password rotation")
	}
	payload, err := json.Marshal(map[string]string{"current": string(current), "replacement": string(replacement)})
	if err != nil {
		return err
	}
	script := `import base64,json,sys,urllib.error,urllib.request
data=json.load(sys.stdin)
old=data["current"].encode(); new=data["replacement"].encode()
auth=lambda value: "Basic "+base64.b64encode(b"admin:"+value).decode("ascii")
change=urllib.request.Request("http://127.0.0.1:3000/api/user/password",data=json.dumps({"oldPassword":old.decode(),"newPassword":new.decode()}).encode(),headers={"Authorization":auth(old),"Content-Type":"application/json"},method="PUT")
try:
  with urllib.request.urlopen(change,timeout=15) as response:
    if response.status not in (200,204): raise RuntimeError("password update rejected")
  verify=urllib.request.Request("http://127.0.0.1:3000/api/user",headers={"Authorization":auth(new)})
  with urllib.request.urlopen(verify,timeout=15) as response:
    if response.status != 200: raise RuntimeError("new password verification rejected")
except (OSError,ValueError,UnicodeError,urllib.error.URLError,urllib.error.HTTPError) as error:
  raise SystemExit("Grafana password rotation failed") from error`
	command := fmt.Sprintf("pct exec %d -- python3 -c %s", b.VMID, shellQuoteValue(script))
	if _, err := stager.RunWithStdin(ctx, command, bytes.NewReader(payload)); err != nil {
		return fmt.Errorf("Grafana password rotation or verification failed: %w", err)
	}
	return nil
}

func serviceHealthy(value string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "active")
}

func BifrostConfig(modules clientservices.Modules) (bifrost.Config, error) {
	if modules.Observability == nil || modules.Observability.Monitoring.Holmes == nil {
		return bifrost.Config{}, errors.New("Monitoring Holmes settings are required")
	}
	h := modules.Observability.Monitoring.Holmes
	config := bifrost.Config{Listen: bifrost.DefaultListen, ClientCredential: h.Bifrost.ClientCredential}
	for _, upstream := range h.Bifrost.Upstreams {
		config.Upstreams = append(config.Upstreams, bifrost.Upstream{Name: upstream.Name, BaseURL: upstream.BaseURL, Credential: upstream.SecretRef})
	}
	for _, candidate := range h.Bifrost.Models {
		config.Models = append(config.Models, bifrost.Model{Alias: candidate.Alias, Upstream: candidate.Upstream, Model: candidate.Model})
	}
	if err := config.Validate(); err != nil {
		return bifrost.Config{}, fmt.Errorf("validate Bifrost configuration: %w", err)
	}
	return config, nil
}

func RequiredSecretNames(modules clientservices.Modules) []string {
	names := []string{"grafana-admin-password"}
	if modules.Observability != nil && modules.Observability.Monitoring.Holmes != nil {
		names = append(names, modules.Observability.Monitoring.Holmes.Bifrost.ClientCredential)
		for _, upstream := range modules.Observability.Monitoring.Holmes.Bifrost.Upstreams {
			names = append(names, upstream.SecretRef)
		}
	}
	if modules.Observability != nil && modules.Observability.Alerts.Pushover != nil && clientservices.Enabled(modules.Observability.Alerts.Pushover.Enabled) {
		names = append(names, pushover.CredentialName)
	}
	if modules.Observability != nil && clientservices.ValidPublicDomain(modules.Observability.PublicDomain) {
		names = append(names, CloudflareCredentialName)
	}
	return names
}

// PushoverEnvironment returns only non-secret alert settings for the guest
// installer. Credentials are projected separately as private service files.
func PushoverEnvironment(modules clientservices.Modules) string {
	config := modules.Observability
	if config == nil || config.Alerts.Pushover == nil || !clientservices.Enabled(config.Alerts.Pushover.Enabled) {
		return ""
	}
	return fmt.Sprintf(" BOETTICHER_OBSERVABILITY_PUSHOVER_ENABLED=true BOETTICHER_OBSERVABILITY_PUSHOVER_TITLE=%s BOETTICHER_OBSERVABILITY_PUSHOVER_PRIORITY=%d", shellQuoteValue(config.Alerts.Pushover.Title), config.Alerts.Pushover.Priority)
}

// CaddyEnvironment returns only the public frontend's non-secret settings.
// The Cloudflare token is projected with systemd LoadCredential by the guest
// installer and never appears in this command string.
func CaddyEnvironment(modules clientservices.Modules, collection CollectionConfig) string {
	if modules.Observability == nil || !clientservices.ValidPublicDomain(modules.Observability.PublicDomain) {
		return ""
	}
	addresses := map[string]string{}
	for _, target := range collection.Targets {
		addresses[target.Name] = target.Address
	}
	if addresses["controller"] == "" || addresses["proxmox-host"] == "" || addresses["lab-monitor-01"] == "" {
		return ""
	}
	return fmt.Sprintf(" BOETTICHER_OBSERVABILITY_PUBLIC_DOMAIN=%s BOETTICHER_OBSERVABILITY_METRICS_CONTROLLER=%s BOETTICHER_OBSERVABILITY_METRICS_HOST=%s BOETTICHER_OBSERVABILITY_METRICS_RUNTIME=%s BOETTICHER_OBSERVABILITY_INGEST_SOURCES=%s", shellQuoteValue(strings.TrimSuffix(strings.ToLower(modules.Observability.PublicDomain), ".")), shellQuoteValue(addresses["controller"]), shellQuoteValue(addresses["proxmox-host"]), shellQuoteValue(addresses["lab-monitor-01"]), shellQuoteValue(addresses["controller"]+" "+addresses["proxmox-host"]+" "+addresses["lab-monitor-01"]))
}

// PayloadDigest binds no-op qualification to the exact installed provider
// catalog, helpers, assets, and binaries rather than intent alone.
func PayloadDigest(root string) (string, error) {
	files := []string{"controller/proxmox/libexec/boetticher-build-observability-base", "controller/observability/base/debian.yaml", "controller/proxmox/libexec/boetticher-install-observability-providers", "controller/observability/assets/catalog.json", "controller/observability/assets/victorialogs.service", "controller/observability/assets/victoriametrics.service", "controller/observability/assets/grafana.service", "controller/observability/assets/grafana-datasource.yaml", "controller/observability/assets/grafana-dashboard.yaml", "controller/observability/assets/grafana-overview.json", "controller/observability/assets/grafana-host-resources.json", "controller/observability/assets/grafana-service-logs.json", "controller/observability/assets/grafana-observability-health.json", "controller/observability/assets/grafana-alerting.yaml", "controller/observability/assets/gatus.service", "controller/observability/assets/gatus.config.yaml", "controller/observability/assets/bifrost.service", "controller/observability/assets/boetticher-incidentd.service", "controller/observability/assets/caddy.service", "controller/observability/bin/caddy", "controller/observability/bin/gatus", "controller/observability/bin/bifrost", "controller/observability/bin/boetticher-incidentd", "controller/observability/holmes/holmes-runner.py", "controller/observability/holmes/holmes.yaml", "controller/observability/holmes/requirements.lock"}
	hash := sha256.New()
	for _, relative := range files {
		data, err := os.ReadFile(root + "/" + relative)
		if err != nil {
			return "", fmt.Errorf("read observability payload %s: %w", relative, err)
		}
		hash.Write([]byte(relative))
		hash.Write([]byte{0})
		hash.Write(data)
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
func parseConfig(raw string) (map[string]string, error) {
	out := map[string]string{}
	for _, l := range strings.Split(raw, "\n") {
		p := strings.SplitN(strings.TrimSpace(l), ": ", 2)
		if len(p) == 2 {
			out[p[0]] = p[1]
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty guest configuration")
	}
	return out, nil
}
