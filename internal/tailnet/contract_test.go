package tailnet

import "testing"

func TestParseNativeRequiresApprovedRouteAndExactPreferences(t *testing.T) {
	status := []byte(`{"BackendState":"Running","Version":"1.102.3","TUN":true,"Self":{"Online":true,"Expired":false,"PrimaryRoutes":["10.10.0.0/16"],"AllowedIPs":[]}}`)
	prefs := []byte(`{"AdvertiseRoutes":["10.10.0.0/16"],"NoSNAT":false,"RouteAll":false,"CorpDNS":false,"WantRunning":true,"ExitNodeID":"","ExitNodeIP":"","RunSSH":false}`)
	if report, err := ParseNative(status, prefs); err != nil || report.State != Healthy {
		t.Fatalf("healthy parse = %#v, %v", report, err)
	}
	unsafe := []byte(`{"AdvertiseRoutes":["10.10.0.0/16"],"NoSNAT":true,"RouteAll":false,"CorpDNS":false,"WantRunning":true,"ExitNodeID":"","ExitNodeIP":"","RunSSH":false}`)
	if report, err := ParseNative(status, unsafe); err != nil || report.State != Failed {
		t.Fatalf("unsafe prefs = %#v, %v", report, err)
	}
	noRoute := []byte(`{"BackendState":"Running","Version":"1.102.3","TUN":true,"Self":{"Online":true,"Expired":false,"PrimaryRoutes":[],"AllowedIPs":[]}}`)
	if report, err := ParseNative(noRoute, prefs); err != nil || report.State != Attention {
		t.Fatalf("unapproved route = %#v, %v", report, err)
	}
}

func TestParseNativeRejectsMalformedStatusAndPreferences(t *testing.T) {
	if _, err := ParseNative([]byte(`{`), []byte(`{}`)); err == nil {
		t.Fatal("malformed status accepted")
	}
	status := []byte(`{"BackendState":"Running","Version":"1.102.3","TUN":true,"Self":{"Online":true,"PrimaryRoutes":["10.10.0.0/16"]}}`)
	if report, err := ParseNative(status, []byte(`{}`)); err != nil || report.State != Failed {
		t.Fatalf("malformed prefs state = %#v, err=%v", report, err)
	}
}
