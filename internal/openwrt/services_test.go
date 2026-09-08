package openwrt

import "testing"

func TestParseServiceListDistinguishesStoppedInstances(t *testing.T) {
	services, err := ParseServiceList([]byte(`{"dnsmasq":{"instances":{"main":{"running":false,"pid":0}}},"stubby":{"instances":{"main":{"running":true}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !services["dnsmasq"].Present || services["dnsmasq"].Running || services["dnsmasq"].Instances != 1 {
		t.Fatalf("stopped dnsmasq was not preserved: %#v", services["dnsmasq"])
	}
	if !services["stubby"].Present || !services["stubby"].Running {
		t.Fatalf("running stubby was not recognised: %#v", services["stubby"])
	}
}

func TestParseServiceListRejectsMalformedResponse(t *testing.T) {
	if _, err := ParseServiceList([]byte(`[]`)); err == nil {
		t.Fatal("array service response was accepted")
	}
}
