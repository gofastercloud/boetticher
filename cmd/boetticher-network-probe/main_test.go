package main

import (
	"errors"
	"reflect"
	"testing"
)

func TestCommandSucceededAcceptsFreeAddressDADResult(t *testing.T) {
	if !commandSucceeded("arping", 1, []byte("..\t100% packet loss (0 extra)\n"), errors.New("exit status 1")) {
		t.Fatal("free-address DAD result was not accepted")
	}
}

func TestCommandSucceededRejectsOccupiedAddressDADResult(t *testing.T) {
	if commandSucceeded("arping", 0, []byte("!!\t0% packet loss (0 extra)\n"), nil) {
		t.Fatal("occupied-address DAD result was accepted")
	}
}

func TestCommandSucceededRejectsArpingSourceFailure(t *testing.T) {
	if commandSucceeded("arping", 1, []byte("Cannot assign requested address\n"), errors.New("exit status 1")) {
		t.Fatal("arping source-address failure was accepted")
	}
}

func TestCommandSucceededUsesNormalExitForOtherProbes(t *testing.T) {
	if !commandSucceeded("ping", 0, nil, nil) {
		t.Fatal("successful non-arping probe was rejected")
	}
	if commandSucceeded("ping", 1, nil, errors.New("exit status 1")) {
		t.Fatal("failed non-arping probe was accepted")
	}
}

func TestCommandSucceededRequiresNmapPortToBeOpen(t *testing.T) {
	if !commandSucceeded("nmap", 0, []byte("443/tcp open https\n"), nil) {
		t.Fatal("open nmap port was rejected")
	}
	for _, output := range []string{
		"443/tcp filtered https\n",
		"443/tcp closed https\n",
	} {
		if commandSucceeded("nmap", 0, []byte(output), nil) {
			t.Fatalf("non-open nmap port was accepted: %q", output)
		}
	}
}

func TestCommandSucceededRequiresSuccessfulDNSAnswer(t *testing.T) {
	if !commandSucceeded("dns", 0, []byte(";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; QUERY: 1, ANSWER: 1, AUTHORITY: 0\n"), nil) {
		t.Fatal("successful DNS answer was rejected")
	}
	for _, output := range []string{
		";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1\n;; QUERY: 1, ANSWER: 0, AUTHORITY: 1\n",
		";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; QUERY: 1, ANSWER: 0, AUTHORITY: 0\n",
	} {
		if commandSucceeded("dns", 0, []byte(output), nil) {
			t.Fatalf("DNS response without an answer was accepted: %q", output)
		}
	}
}

func TestCurlArgumentsPinModeledEndpointWhilePreservingTLSHost(t *testing.T) {
	args, err := curlArguments(request{Kind: "mtls", URL: "https://monitor.lab.home.arpa", Target: "10.10.10.20", CA: "ca", Cert: "cert", Key: "key"})
	if err != nil {
		t.Fatal(err)
	}
	wantResolve := []string{"--resolve", "monitor.lab.home.arpa:443:10.10.10.20"}
	for i := range args {
		if i+1 < len(args) && args[i] == wantResolve[0] && args[i+1] == wantResolve[1] {
			return
		}
	}
	t.Fatalf("curl arguments did not pin modeled endpoint: %#v", args)
}

func TestRunUsesIdempotentNetworkConfiguration(t *testing.T) {
	for _, test := range []struct {
		name    string
		request request
		want    []string
	}{
		{name: "address", request: request{Version: 1, Kind: "configure", Target: "10.10.5.250"}, want: []string{"addr", "replace", "10.10.5.250/24", "dev", "eth0"}},
		{name: "route", request: request{Version: 1, Kind: "route", Target: "10.10.5.1"}, want: []string{"route", "replace", "default", "via", "10.10.5.1"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := networkConfigurationArguments(test.request.Kind, test.request.Target)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("command arguments = %#v, want %#v", got, test.want)
			}
		})
	}
}
