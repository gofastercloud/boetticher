package model

import "testing"

func TestUserFirewallRuleValidationIsBoundedAndCoreSafe(t *testing.T) {
	site := NewDefaultSite("installation", "age1example")
	site.Components = append(site.Components, Component{Name: "core-service", Hostname: "core-service", VMID: 201, Zone: "SERVERS", Address: "10.10.20.60", Role: "Core service", ProductOwned: true, Tags: []string{TagBoetticher, TagManaged}})
	site.UserFirewallRules = []UserFirewallRule{{ID: "ufr-example", Source: "TRUSTED", Destination: "10.10.20.61/32", Protocol: "tcp", Ports: []string{"443", "8000-8002"}}}
	if err := site.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, rule := range []UserFirewallRule{
		{ID: "ufr-zone", Source: "TRUSTED", Destination: "SERVERS", Protocol: "tcp", Ports: []string{"443"}},
		{ID: "ufr-bad", Source: "TRUSTED", Destination: "10.10.99.5/32", Protocol: "tcp", Ports: []string{"22"}},
		{ID: "ufr-bad", Source: "TRUSTED", Destination: "10.10.20.61/32", Protocol: "tcp", Ports: []string{"1-1025"}},
	} {
		site.UserFirewallRules = []UserFirewallRule{rule}
		if err := site.Validate(); err == nil {
			t.Errorf("unsafe rule %#v was accepted", rule)
		}
	}
}

func TestReservedServersClientMayReachPulseHTTPS(t *testing.T) {
	site := NewDefaultSite("installation", "age1example")
	site.DHCPReservations = []DHCPReservation{{Zone: "SERVERS", Hostname: "lab-display-01", Address: "10.10.20.50", MAC: "dc:a6:32:e9:dd:82"}}
	site.UserFirewallRules = []UserFirewallRule{{ID: "ufr-lab-display-pulse", Source: "10.10.20.50/32", Destination: "10.10.10.20/32", Protocol: "tcp", Ports: []string{"443"}}}
	if err := site.Validate(); err != nil {
		t.Fatalf("reserved SERVERS Pulse client was rejected: %v", err)
	}
}

func TestPulseClientRuleRemainsNarrowAndReservationBound(t *testing.T) {
	base := NewDefaultSite("installation", "age1example")
	base.DHCPReservations = []DHCPReservation{{Zone: "SERVERS", Hostname: "lab-display-01", Address: "10.10.20.50", MAC: "dc:a6:32:e9:dd:82"}}
	for _, rule := range []UserFirewallRule{
		{ID: "ufr-broad", Source: "SERVERS", Destination: "10.10.10.20/32", Protocol: "tcp", Ports: []string{"443"}},
		{ID: "ufr-unreserved", Source: "10.10.20.51/32", Destination: "10.10.10.20/32", Protocol: "tcp", Ports: []string{"443"}},
		{ID: "ufr-other-core", Source: "10.10.20.50/32", Destination: "10.10.10.11/32", Protocol: "tcp", Ports: []string{"443"}},
		{ID: "ufr-other-port", Source: "10.10.20.50/32", Destination: "10.10.10.20/32", Protocol: "tcp", Ports: []string{"8443"}},
	} {
		site := base
		site.UserFirewallRules = []UserFirewallRule{rule}
		if err := site.Validate(); err == nil {
			t.Errorf("unsafe Pulse client rule was accepted: %#v", rule)
		}
	}
}

func TestUserFirewallRuleLimitAndEquivalentDuplicate(t *testing.T) {
	site := NewDefaultSite("installation", "age1example")
	for i := 0; i < maxUserFirewallRules+1; i++ {
		site.UserFirewallRules = append(site.UserFirewallRules, UserFirewallRule{ID: "ufr-" + string(rune('a'+i)), Source: "TRUSTED", Destination: "10.10.20.61/32", Protocol: "tcp", Ports: []string{string(rune('4'+i%5)) + "43"}})
	}
	if err := site.Validate(); err == nil {
		t.Fatal("more than 64 firewall rules were accepted")
	}
	site.UserFirewallRules = []UserFirewallRule{{ID: "ufr-a", Source: "TRUSTED", Destination: "10.10.20.61/32", Protocol: "TCP", Ports: []string{"443"}}, {ID: "ufr-b", Source: "trusted", Destination: "10.10.20.61/32", Protocol: "tcp", Ports: []string{"443"}}}
	if err := site.Validate(); err == nil {
		t.Fatal("semantically equivalent rules were accepted")
	}
}
