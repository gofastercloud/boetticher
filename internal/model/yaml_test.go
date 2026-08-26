package model

import (
	"os"
	"testing"
)

func TestParseSiteYAMLSubset(t *testing.T) {
	data := []byte(`api_version: boetticher/v1
platform_version: 0.1.0
schema_version: 1
storage_profile: single-disk
tested_versions:
  opnsense: 26.7.2_2
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
	site, err := ParseSite(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := site.Validate(); err != nil {
		t.Fatal(err)
	}
}
