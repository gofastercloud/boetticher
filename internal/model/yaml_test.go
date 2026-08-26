package model

import (
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
  zabbix: "7.0 LTS"
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

func TestDNSProviderIsTypedAndStrict(t *testing.T) {
	config, err := ParseSiteConfig([]byte("api_version: boetticher/v3\nmodules:\n  dns:\n    provider: adguard\n"))
	if err != nil || config.Modules["dns"].Provider != "adguard" {
		t.Fatalf("adguard provider was not accepted: %#v %v", config, err)
	}
	if _, err := ParseSiteConfig([]byte("api_version: boetticher/v3\nmodules:\n  monitoring:\n    provider: blocky\n")); err == nil || !strings.Contains(err.Error(), "modules.monitoring.provider") {
		t.Fatalf("irrelevant provider was accepted: %v", err)
	}
	if _, err := ParseSiteConfig([]byte("api_version: boetticher/v3\nmodules:\n  dns:\n    enabled: false\n")); err == nil || !strings.Contains(err.Error(), "mandatory module") {
		t.Fatalf("DNS disable was accepted: %v", err)
	}
}

func TestParseSiteConfigRejectsUnknownModuleName(t *testing.T) {
	_, err := ParseSiteConfig([]byte("api_version: boetticher/v3\nmodules:\n  monitroing:\n    enabled: true\n"))
	if err == nil || !strings.Contains(err.Error(), "modules.monitroing") {
		t.Fatalf("unknown module name was accepted: %v", err)
	}
}
