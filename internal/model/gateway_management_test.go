package model

import (
	"strings"
	"testing"
)

func TestGatewayManagementIntentUsesReferenceHOMEBindings(t *testing.T) {
	site := NewSite("installation", "age1example", GatewayModeManaged)
	if site.Gateway.ManagementAddress != "192.168.4.28" || site.Gateway.ManagementNetwork != "192.168.4.0/22" || site.Gateway.ManagementGateway != "192.168.4.1" || site.Gateway.ControllerAddress != "192.168.4.6" {
		t.Fatalf("reference HOME bindings = %#v", site.Gateway)
	}
	if err := site.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestGatewayManagementIntentRejectsOutOfPrefixValues(t *testing.T) {
	for _, edit := range []func(*Site){
		func(site *Site) { site.Gateway.ManagementNetwork = "192.168.0.0/24" },
		func(site *Site) { site.Gateway.ManagementGateway = "10.0.0.1" },
		func(site *Site) { site.Gateway.ControllerAddress = "10.0.0.6" },
	} {
		site := NewSite("installation", "age1example", GatewayModeManaged)
		edit(&site)
		if err := site.Validate(); err == nil || !strings.Contains(err.Error(), "gateway.") {
			t.Fatalf("invalid HOME binding was accepted: %v", err)
		}
	}
}
