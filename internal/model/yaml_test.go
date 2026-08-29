package model

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestParseSiteYAMLSubset(t *testing.T) {
	data := []byte(`api_version: boetticher/v2
platform_version: 0.2.0
schema_version: 2
storage_profile: single-disk
gateway:
  mode: managed
tested_versions:
  gateway: debian-13-genericcloud-amd64-20260327-2429
  pulse: "6.1.2"
network:
  domain: lab.home.arpa
  zones:
    - name: MGMT
      vlan: 99
      network: 10.10.99.0/24
      gateway: 10.10.99.1
      address_mode: reservations-only
      dns_addresses: [10.10.20.10, 10.10.20.11]
      ntp_addresses: [10.10.20.10, 10.10.20.11]
secret_metadata:
  installation_id: installation
  age_recipient: age1example
pki: {}
components:
  - name: host
    hostname: host
    zone: MGMT
    address: 10.10.99.5
    role: host
    monitoring: true
    backup: true
    ssh_managed: true
    jump_allowed: true
    product_owned: true
`)
	site, err := ParseSite(data)
	if err != nil {
		t.Fatal(err)
	}
	if site.Network.Zones[0].VLAN != 99 || site.Components[0].Name != "host" {
		t.Fatalf("unexpected parsed site: %+v", site)
	}
}

func TestExampleSiteIsValid(t *testing.T) {
	data, err := os.ReadFile("../../site.example.yml")
	if err != nil {
		t.Fatal(err)
	}
	config, err := ParseSiteConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestParseSiteConfigRejectsExpandedComponents(t *testing.T) {
	data := []byte("api_version: boetticher/v3\nschema_version: 3\ncomponents: []\n")
	_, err := ParseSiteConfig(data)
	if err == nil || !strings.Contains(err.Error(), "field components not found") {
		t.Fatalf("expanded component inventory was accepted: %v", err)
	}
}

func TestParseSiteConfigDoesNotAcceptLiveProxmoxNodeBinding(t *testing.T) {
	data := []byte("api_version: boetticher/v3\nschema_version: 3\nproxmox_node: lab-proxmox-01\n")
	_, err := ParseSiteConfig(data)
	if err == nil || !strings.Contains(err.Error(), "field proxmox_node not found") {
		t.Fatalf("live Proxmox node binding was accepted as site configuration: %v", err)
	}
}

func TestParseSiteConfigRejectsUnknownModuleFields(t *testing.T) {
	data := []byte("api_version: boetticher/v3\nschema_version: 3\nmodules:\n  monitoring:\n    retention_days: 7\n")
	_, err := ParseSiteConfig(data)
	if err == nil || !strings.Contains(err.Error(), "retention_days") {
		t.Fatalf("unknown module field was accepted: %v", err)
	}
}

func TestParseSiteConfigAppliesV3Defaults(t *testing.T) {
	config, err := ParseSiteConfig([]byte("api_version: boetticher/v3\nmodules: {}\nsecret_metadata:\n  installation_id: test\n  age_recipient: age1test\n"))
	if err != nil {
		t.Fatal(err)
	}
	site := config.BaseSite()
	if err := site.Validate(); err != nil {
		t.Fatalf("defaults should produce a valid site: %v", err)
	}
	if site.Gateway.Mode != GatewayModeManaged || site.StorageProfile != "single-disk" || site.Network.Domain != DefaultDomain {
		t.Fatalf("unexpected defaults: gateway=%q storage=%q domain=%q", site.Gateway.Mode, site.StorageProfile, site.Network.Domain)
	}
}

func TestGatewayPublicationConfigRoundTrips(t *testing.T) {
	config, err := ParseSiteConfig([]byte(`api_version: boetticher/v3
gateway:
  mode: managed
  upstream:
    mode: dhcp
    mac: 02:8f:4c:91:a7:32
  publish:
    - service: dns
modules: {}
secret_metadata:
  installation_id: test
  age_recipient: age1test
`))
	if err != nil {
		t.Fatal(err)
	}
	if config.Gateway.Upstream.Mode != "dhcp" || config.Gateway.Upstream.MAC != "02:8f:4c:91:a7:32" || len(config.Gateway.Publish) != 1 || config.Gateway.Publish[0].Service != "dns" {
		t.Fatalf("unexpected gateway publication config: %#v", config.Gateway)
	}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	rendered, err := RenderSiteConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := ParseSiteConfig(rendered)
	if err != nil {
		t.Fatal(err)
	}
	if roundTrip.Gateway.Upstream.MAC != config.Gateway.Upstream.MAC || len(roundTrip.Gateway.Publish) != 1 {
		t.Fatalf("gateway publication config did not round-trip: %s", rendered)
	}
}

func TestParseSiteConfigRetainsReservationsAndUserDNSValues(t *testing.T) {
	config, err := ParseSiteConfig([]byte(`api_version: boetticher/v3
secret_metadata:
  installation_id: test
  age_recipient: age1test
dhcp_reservations:
  - zone: SERVERS
    hostname: app-01
    address: 10.10.20.61
    mac: 02:00:00:00:02:61
dns_records:
  - name: app.lab.home.arpa
    type: CNAME
    value: app-01.servers.lab.home.arpa
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(config.DHCPReservations) != 1 || len(config.DNSRecords) != 1 || config.DNSRecords[0].Value != "app-01.servers.lab.home.arpa" {
		t.Fatalf("operator records were not retained: %#v %#v", config.DHCPReservations, config.DNSRecords)
	}
	rendered, err := RenderSiteConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := ParseSiteConfig(rendered)
	if err != nil {
		t.Fatal(err)
	}
	if roundTrip.DNSRecords[0].Value != "app-01.servers.lab.home.arpa" {
		t.Fatalf("rendered user CNAME did not retain value: %s", rendered)
	}
}

func TestDNSProviderIsTypedAndStrict(t *testing.T) {
	config, err := ParseSiteConfig([]byte("api_version: boetticher/v3\nmodules:\n  dns:\n    provider: adguard\n"))
	if err != nil || config.Modules.DNS == nil || config.Modules.DNS.Provider != DNSProviderAdGuard {
		t.Fatalf("adguard provider was not accepted: %#v %v", config, err)
	}
	if _, err := ParseSiteConfig([]byte("api_version: boetticher/v3\nmodules:\n  monitoring:\n    provider: blocky\n")); err == nil || !strings.Contains(err.Error(), "modules.monitoring.provider") {
		t.Fatalf("irrelevant provider was accepted: %v", err)
	}
	if _, err := ParseSiteConfig([]byte("api_version: boetticher/v3\nmodules:\n  dns:\n    enabled: false\n")); err == nil || !strings.Contains(err.Error(), "mandatory module") {
		t.Fatalf("DNS disable was accepted: %v", err)
	}
	if _, err := ParseSiteConfig([]byte("api_version: boetticher/v3\nmodules:\n  logging:\n    enabled: false\n")); err == nil || !strings.Contains(err.Error(), "modules.logging.enabled") {
		t.Fatalf("logging disable was accepted: %v", err)
	}
}

func TestFirewallBackendIsTypedAndRoundTripsThroughGenericConfiguration(t *testing.T) {
	config, err := ParseSiteConfig([]byte("api_version: boetticher/v3\nmodules:\n  firewall:\n    backend: lxc\nsecret_metadata:\n  installation_id: test\n  age_recipient: age1test\n"))
	if err != nil {
		t.Fatal(err)
	}
	if config.Modules.Firewall == nil || config.Modules.Firewall.Backend != FirewallBackendLXC {
		t.Fatalf("unexpected typed firewall backend: %#v", config.Modules.Firewall)
	}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	rendered, err := RenderSiteConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := ParseSiteConfig(rendered)
	if err != nil || roundTrip.Modules.Firewall == nil || roundTrip.Modules.Firewall.Backend != FirewallBackendLXC {
		t.Fatalf("firewall backend did not round-trip: %v %s", err, rendered)
	}
	if _, err := ParseSiteConfig([]byte("api_version: boetticher/v3\nmodules:\n  firewall:\n    backend: privileged-lxc\n")); err == nil || !strings.Contains(err.Error(), "modules.firewall.backend") {
		t.Fatalf("invalid firewall backend was accepted: %v", err)
	}
}

func TestParseSiteConfigRejectsUnknownModuleName(t *testing.T) {
	_, err := ParseSiteConfig([]byte("api_version: boetticher/v3\nmodules:\n  monitroing:\n    enabled: true\n"))
	if err == nil || !strings.Contains(err.Error(), "modules.monitroing") {
		t.Fatalf("unknown module name was accepted: %v", err)
	}
}

func TestLiteLLMConfigIsStrictAndProviderNeutral(t *testing.T) {
	valid := []byte(`api_version: boetticher/v3
modules:
  litellm:
    upstreams:
      - name: openrouter
        base_url: https://openrouter.ai/api/v1
        api_key_secret: openrouter_api_key
    models:
      - alias: selected-alias
        upstream: openrouter
        model: selected/openrouter-model
secret_metadata:
  installation_id: test
  age_recipient: age1test
`)
	config, err := ParseSiteConfig(valid)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	model, err := ResolveLiteLLMAlias(config.Modules.Map()["litellm"], "selected-alias")
	if err != nil || model.Model != "selected/openrouter-model" {
		t.Fatalf("declared alias resolution = %#v, %v", model, err)
	}
	if _, err := ResolveLiteLLMAlias(config.Modules.Map()["litellm"], "selected/openrouter-model"); err == nil {
		t.Fatal("provider model identifier was accepted as a public alias")
	}
	if _, err := ParseSiteConfig([]byte(`api_version: boetticher/v3
modules:
  litellm:
    upstreams:
      - name: openrouter
        base_url: https://openrouter.ai/api/v1
        api_key_secret: openrouter_api_key
    models:
      - alias: selected-alias
        upstream: openrouter
        model: selected/openrouter-model
        unknown: true
`)); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown LiteLLM model field was accepted: %v", err)
	}
}

func TestLiteLLMConfigRejectsInvalidReferencesAndDuplicates(t *testing.T) {
	cases := []string{
		`api_version: boetticher/v3
modules:
  litellm:
    upstreams: []
    models: [{alias: selected, upstream: openrouter, model: model}]`,
		`api_version: boetticher/v3
modules:
  litellm:
    upstreams:
      - {name: openrouter, base_url: http://openrouter.ai/api/v1, api_key_secret: key}
    models: [{alias: selected, upstream: openrouter, model: model}]`,
		`api_version: boetticher/v3
modules:
  litellm:
    upstreams:
      - {name: openrouter, base_url: https://openrouter.ai/api/v1, api_key_secret: key}
      - {name: openrouter, base_url: https://other.example/api/v1, api_key_secret: key2}
    models: [{alias: selected, upstream: openrouter, model: model}]`,
		`api_version: boetticher/v3
modules:
  litellm:
    upstreams:
      - {name: openrouter, base_url: https://openrouter.ai/api/v1, api_key_secret: key}
    models: [{alias: selected, upstream: missing, model: model}]`,
		`api_version: boetticher/v3
modules:
  litellm:
    upstreams:
      - {name: openrouter, base_url: https://openrouter.ai/api/v1, api_key_secret: key}
    models: []`,
		`api_version: boetticher/v3
modules:
  litellm:
    upstreams:
      - {name: openrouter, base_url: https://openrouter.ai/api/v1, api_key_secret: ../key}
    models: [{alias: selected, upstream: openrouter, model: model}]`,
		`api_version: boetticher/v3
modules:
  litellm:
    upstreams:
      - {name: openrouter, base_url: "https://openrouter.ai/api/v1?token=bad", api_key_secret: key}
    models: [{alias: selected, upstream: openrouter, model: model}]`,
		`api_version: boetticher/v3
modules:
  litellm:
    upstreams:
      - {name: openrouter, base_url: https://openrouter.ai/api/v1, api_key_secret: key}
    models:
      - {alias: "selected alias", upstream: openrouter, model: model}`,
		`api_version: boetticher/v3
modules:
  litellm:
    upstreams:
      - {name: openrouter, base_url: https://openrouter.ai/api/v1, api_key_secret: key}
    models:
      - {alias: selected, upstream: openrouter, model: model}
      - {alias: selected, upstream: openrouter, model: other-model}`,
	}
	for index, data := range cases {
		t.Run(fmt.Sprintf("case-%d", index), func(t *testing.T) {
			config, err := ParseSiteConfig([]byte(data))
			if err != nil {
				t.Fatal(err)
			}
			if err := config.Validate(); err == nil {
				t.Fatal("invalid LiteLLM configuration was accepted")
			}
		})
	}
}

func TestDisabledLiteLLMMayOmitRuntimeConfiguration(t *testing.T) {
	config, err := ParseSiteConfig([]byte(`api_version: boetticher/v3
modules:
  litellm:
    enabled: false
secret_metadata:
  installation_id: test
  age_recipient: age1test
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("default-off LiteLLM should not require unused runtime config: %v", err)
	}
}

func TestAIOpsConfigurationIsStrictAndProviderNeutral(t *testing.T) {
	data := []byte(`api_version: boetticher/v3
platform_version: 0.3.33
schema_version: 3
modules:
  aiops:
    enabled: true
    model_alias: operations-investigator
`)
	config, err := ParseSiteConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	if config.Modules.AIOps == nil || config.Modules.AIOps.ModelAlias != "operations-investigator" {
		t.Fatalf("unexpected aiops config: %#v", config.Modules.AIOps)
	}
	for _, field := range []string{"provider", "model", "api_key", "ssh_probes", "tools"} {
		invalid := bytes.Replace(data, []byte("    model_alias: operations-investigator\n"), []byte("    model_alias: operations-investigator\n    "+field+": forbidden\n"), 1)
		if _, err := ParseSiteConfig(invalid); err == nil {
			t.Fatalf("aiops field %s was accepted", field)
		}
	}
}
