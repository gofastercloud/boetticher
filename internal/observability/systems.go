package observability

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	"gopkg.in/yaml.v3"
)

const (
	gatusConfigPath          = "/etc/boetticher/gatus/config.yaml"
	gatusSystemsGroup        = "boetticher-operator-systems"
	gatusSystemNamePrefix    = "boetticher-system-"
	maxGatusConfigBytes      = 512 * 1024
	gatusSystemCheckInterval = "30s"
)

// MediaGatusEndpoints derives media health checks from typed media intent.
// The monitor reaches the guest's dedicated internal Caddy health listener;
// application admin ports remain loopback-only in the media VM.
func MediaGatusEndpoints(modules clientservices.Modules) ([]map[string]interface{}, error) {
	if modules.Media == nil || !modules.Media.Enabled {
		return nil, nil
	}
	if modules.Media.ApplicationDomain == "" {
		return nil, errors.New("enabled media monitoring requires an application domain")
	}
	services := []struct{ name, alias, path string }{
		{"caddy", "caddy", ""},
		{"qbittorrent", "qbittorrent", ""}, {"prowlarr", modules.Media.Aliases.Prowlarr, "ping"},
		{"sonarr", modules.Media.Aliases.Sonarr, "ping"}, {"radarr", modules.Media.Aliases.Radarr, "ping"},
		{"bazarr", modules.Media.Aliases.Bazarr, "api/system/ping"}, {"ai-subtitle-translator", "ai-subtitle-translator", "health"},
		{"flaresolverr", "flaresolverr", "health"}, {"jellyfin", "jellyfin", "health"},
		{"jellyseerr", "jellyseerr", "api/v1/status"}, {"trailarr", modules.Media.Aliases.Trailarr, "status"},
	}
	result := make([]map[string]interface{}, 0, len(services))
	for _, service := range services {
		if service.alias == "" {
			return nil, fmt.Errorf("media monitoring alias for %s is empty", service.name)
		}
		path := "/" + strings.TrimPrefix(service.path, "/")
		result = append(result, map[string]interface{}{
			"name": "boetticher-media-" + service.name, "group": "boetticher-media",
			"url": "http://10.10.20.230:9110" + path, "method": "GET",
			"headers":  map[string]string{"Host": service.alias + "." + modules.Media.ApplicationDomain, "Cookie": "", "Authorization": ""},
			"interval": "30s", "conditions": []string{"[STATUS] == 200"},
		})
	}
	return result, nil
}

// ReconcileGatus projects registered systems into the existing, owned Gatus
// configuration. It does not create, change, or remove operator system guests.
func (c HostClient) ReconcileGatus(ctx context.Context, base []byte, systems []clientservices.System, mediaModules ...clientservices.Modules) error {
	if len(base) == 0 {
		return errors.New("Gatus configuration is required")
	}
	payload, err := RenderGatusConfig(base, systems, mediaModules...)
	if err != nil {
		return err
	}
	if len(payload) > maxGatusConfigBytes {
		return errors.New("rendered Gatus configuration exceeds the bounded size")
	}
	observation, err := c.ObserveGuest(ctx, binding)
	if err != nil {
		return err
	}
	if observation.State != "owned" {
		return fmt.Errorf("observability guest is %s", observation.State)
	}
	ready, err := c.GatusSystemsHealthy(ctx, systems, mediaModules...)
	if err == nil && ready {
		return nil
	}
	runner, ok := c.Transport.(StdinRunner)
	if !ok {
		return errors.New("observability transport does not support bounded stdin")
	}
	_, err = runner.RunWithStdin(ctx, gatusReplaceCommand(), bytes.NewReader(payload))
	if err != nil {
		// Do not reflect provider stderr: it can include configuration diagnostics.
		return errors.New("Gatus configuration replacement or health verification failed")
	}
	readback, err := c.GatusConfigStatus(ctx)
	if err != nil {
		return fmt.Errorf("read back Gatus configuration: %w", err)
	}
	matched, err := gatusSystemsMatch([]byte(readback), systems, mediaModules...)
	if err != nil {
		return fmt.Errorf("verify Gatus system projection: %w", err)
	}
	if !matched {
		return errors.New("Gatus system projection did not persist")
	}
	status, err := c.ServiceStatus(ctx, binding, "gatus.service")
	if err != nil || !serviceHealthy(status) {
		return errors.New("Gatus service is not active after configuration replacement")
	}
	if _, err := c.ProviderHealth(ctx, binding, "gatus.service"); err != nil {
		return fmt.Errorf("verify Gatus health after configuration replacement: %w", err)
	}
	return nil
}

// GatusConfigStatus reads the owned provider configuration without mutation.
func (c HostClient) GatusConfigStatus(ctx context.Context) (string, error) {
	observation, err := c.ObserveGuest(ctx, binding)
	if err != nil {
		return "", err
	}
	if observation.State != "owned" {
		return "", fmt.Errorf("observability guest is %s", observation.State)
	}
	r, err := c.Transport.Run(ctx, fmt.Sprintf("pct exec %d -- cat %s", binding.VMID, shellQuoteValue(gatusConfigPath)))
	if err != nil {
		return "", err
	}
	if len(r.Stdout) > maxGatusConfigBytes {
		return "", errors.New("Gatus configuration exceeds the bounded size")
	}
	return string(r.Stdout), nil
}

// GatusSystemsHealthy is the read-only no-op gate for registered-system
// projection. It requires the exact desired projection and a live Gatus unit.
func (c HostClient) GatusSystemsHealthy(ctx context.Context, systems []clientservices.System, mediaModules ...clientservices.Modules) (bool, error) {
	config, err := c.GatusConfigStatus(ctx)
	if err != nil {
		return false, err
	}
	matched, err := gatusSystemsMatch([]byte(config), systems, mediaModules...)
	if err != nil || !matched {
		return false, err
	}
	status, err := c.ServiceStatus(ctx, binding, "gatus.service")
	if err != nil || !serviceHealthy(status) {
		return false, err
	}
	if _, err := c.ProviderHealth(ctx, binding, "gatus.service"); err != nil {
		return false, err
	}
	return true, nil
}

// RenderGatusConfig appends exact, namespaced TCP checks for registered
// operator systems. Only endpoints bearing both the reserved group and exact
// generated name are owned; same-group foreign endpoints remain untouched.
func RenderGatusConfig(base []byte, systems []clientservices.System, mediaModules ...clientservices.Modules) ([]byte, error) {
	var config map[string]interface{}
	if err := yaml.Unmarshal(base, &config); err != nil {
		return nil, fmt.Errorf("decode Gatus configuration: %w", err)
	}
	if config == nil {
		return nil, errors.New("Gatus configuration must be a mapping")
	}
	rawEndpoints, exists := config["endpoints"]
	if !exists {
		return nil, errors.New("Gatus configuration has no endpoints list")
	}
	endpoints, ok := rawEndpoints.([]interface{})
	if !ok {
		return nil, errors.New("Gatus endpoints must be a list")
	}
	desired, err := desiredGatusSystemEndpoints(systems)
	if err != nil {
		return nil, err
	}
	mediaDesired := make(map[string]interface{})
	if len(mediaModules) > 0 {
		media, err := MediaGatusEndpoints(mediaModules[0])
		if err != nil {
			return nil, err
		}
		for _, endpoint := range media {
			mediaDesired[endpoint["name"].(string)] = endpoint
		}
	}
	kept := make([]interface{}, 0, len(endpoints)+len(desired))
	for _, raw := range endpoints {
		endpoint, ok := raw.(map[string]interface{})
		if !ok {
			return nil, errors.New("Gatus endpoint must be a mapping")
		}
		name, _ := endpoint["name"].(string)
		if isOwnedGatusSystemEndpoint(endpoint) {
			continue
		}
		if isOwnedMediaEndpoint(endpoint) {
			if _, exists := mediaDesired[name]; !exists {
				return nil, fmt.Errorf("Gatus endpoint %q conflicts with the reserved media identity", name)
			}
			continue
		}
		if _, reserved := desired[name]; reserved {
			return nil, fmt.Errorf("Gatus endpoint %q conflicts with the reserved operator-system identity", name)
		}
		if _, reserved := mediaDesired[name]; reserved {
			return nil, fmt.Errorf("Gatus endpoint %q conflicts with the reserved media identity", name)
		}
		kept = append(kept, endpoint)
	}
	names := make([]string, 0, len(desired))
	for name := range desired {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		kept = append(kept, desired[name])
	}
	mediaNames := make([]string, 0, len(mediaDesired))
	for name := range mediaDesired {
		mediaNames = append(mediaNames, name)
	}
	sort.Strings(mediaNames)
	for _, name := range mediaNames {
		kept = append(kept, mediaDesired[name])
	}
	config["endpoints"] = kept
	out, err := yaml.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("encode Gatus configuration: %w", err)
	}
	return out, nil
}

func isOwnedMediaEndpoint(endpoint map[string]interface{}) bool {
	name, nameOK := endpoint["name"].(string)
	group, groupOK := endpoint["group"].(string)
	return nameOK && groupOK && group == "boetticher-media" && strings.HasPrefix(name, "boetticher-media-")
}

func desiredGatusSystemEndpoints(systems []clientservices.System) (map[string]map[string]interface{}, error) {
	desired := make(map[string]map[string]interface{})
	for _, system := range systems {
		if !system.Monitoring {
			continue
		}
		if err := validateSystem(system); err != nil {
			return nil, err
		}
		name := gatusSystemNamePrefix + system.Name
		if _, duplicate := desired[name]; duplicate {
			return nil, fmt.Errorf("duplicate monitored system %q", system.Name)
		}
		desired[name] = map[string]interface{}{
			"name":       name,
			"group":      gatusSystemsGroup,
			"url":        fmt.Sprintf("tcp://%s:%d", system.Address, system.Port),
			"interval":   gatusSystemCheckInterval,
			"conditions": []string{"[CONNECTED] == true"},
		}
	}
	return desired, nil
}

func gatusSystemsMatch(config []byte, systems []clientservices.System, mediaModules ...clientservices.Modules) (bool, error) {
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(config, &parsed); err != nil {
		return false, fmt.Errorf("decode Gatus configuration: %w", err)
	}
	rawEndpoints, ok := parsed["endpoints"].([]interface{})
	if !ok {
		return false, errors.New("Gatus endpoints must be a list")
	}
	desired, err := desiredGatusSystemEndpoints(systems)
	if err != nil {
		return false, err
	}
	mediaDesired := map[string]map[string]interface{}{}
	if len(mediaModules) > 0 {
		media, err := MediaGatusEndpoints(mediaModules[0])
		if err != nil {
			return false, err
		}
		for _, endpoint := range media {
			mediaDesired[endpoint["name"].(string)] = endpoint
		}
	}
	found := make(map[string]bool, len(desired))
	for _, raw := range rawEndpoints {
		endpoint, ok := raw.(map[string]interface{})
		if !ok {
			return false, errors.New("Gatus endpoint must be a mapping")
		}
		if !isOwnedGatusSystemEndpoint(endpoint) && !isOwnedMediaEndpoint(endpoint) {
			continue
		}
		name, _ := endpoint["name"].(string)
		expected, exists := desired[name]
		if !exists {
			expected, exists = mediaDesired[name]
		}
		if !exists || found[name] || !sameGatusSystemEndpoint(endpoint, expected) {
			return false, nil
		}
		found[name] = true
	}
	return len(found) == len(desired)+len(mediaDesired), nil
}

func isOwnedGatusSystemEndpoint(endpoint map[string]interface{}) bool {
	name, nameOK := endpoint["name"].(string)
	group, groupOK := endpoint["group"].(string)
	return nameOK && groupOK && group == gatusSystemsGroup && strings.HasPrefix(name, gatusSystemNamePrefix) && validSystemEndpointSuffix(strings.TrimPrefix(name, gatusSystemNamePrefix))
}

func validSystemEndpointSuffix(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !(r == '-' || r == '_' || r == '.' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func sameGatusSystemEndpoint(actual, expected map[string]interface{}) bool {
	if actual["group"] == "boetticher-media" {
		for _, key := range []string{"name", "group", "url", "method", "interval"} {
			if actual[key] != expected[key] {
				return false
			}
		}
		return fmt.Sprint(actual["conditions"]) == fmt.Sprint(expected["conditions"]) && fmt.Sprint(actual["headers"]) == fmt.Sprint(expected["headers"])
	}
	for _, key := range []string{"name", "group", "url", "interval"} {
		if actual[key] != expected[key] {
			return false
		}
	}
	conditions, ok := actual["conditions"].([]interface{})
	return ok && len(conditions) == 1 && conditions[0] == "[CONNECTED] == true"
}

func validateSystem(s clientservices.System) error {
	if s.Name == "" || !validSystemEndpointSuffix(s.Name) || s.GuestName == "" || (s.Kind != "lxc" && s.Kind != "qemu") || s.VMID < 100 || s.Port < 1 || s.Port > 65535 {
		return fmt.Errorf("monitored system %q has invalid identity or port", s.Name)
	}
	ip, err := netip.ParseAddr(s.Address)
	if err != nil || !ip.Is4() {
		return fmt.Errorf("monitored system %q has invalid address", s.Name)
	}
	return nil
}

func gatusReplaceCommand() string {
	// The directory is root-owned 0750 and the service is gatus, so all path
	// components and the installed file are checked before the same-directory
	// atomic rename. The previous bytes are restored if reload or health fails.
	return "set -eu; dir=/etc/boetticher/gatus; target=/etc/boetticher/gatus/config.yaml; for path in /etc /etc/boetticher \"$dir\" \"$target\"; do test ! -L \"$path\"; done; test -d \"$dir\"; test -f \"$target\"; tmp=$(mktemp \"$dir/.config.yaml.new.XXXXXX\"); old=$(mktemp \"$dir/.config.yaml.old.XXXXXX\"); cleanup(){ rm -f \"$tmp\" \"$old\"; }; wait_health(){ for attempt in 1 2 3 4 5 6 7 8 9 10; do if curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8080/health >/dev/null; then return 0; fi; sleep 1; done; return 1; }; trap cleanup EXIT HUP INT TERM; cat > \"$tmp\"; test \"$(wc -c < \"$tmp\")\" -le 524288; chown root:gatus \"$tmp\"; chmod 0640 \"$tmp\"; if cmp -s \"$tmp\" \"$target\"; then systemctl is-active --quiet gatus.service; wait_health; exit 0; fi; cp -p \"$target\" \"$old\"; mv -f \"$tmp\" \"$target\"; if ! systemctl reload-or-restart gatus.service || ! systemctl is-active --quiet gatus.service || ! wait_health; then mv -f \"$old\" \"$target\"; systemctl reload-or-restart gatus.service || true; wait_health || true; exit 1; fi; rm -f \"$old\""
}
