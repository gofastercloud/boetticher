package main

import (
	"strings"
	"testing"
)

func TestValidateNTPResponseRejectsUnsynchronisedAndAcceptsMeaningfulReply(t *testing.T) {
	unsynchronised := make([]byte, 48)
	unsynchronised[0] = 0x24
	if err := validateNTPResponse(unsynchronised); err == nil {
		t.Fatal("unsynchronised NTP response was accepted")
	}
	response := make([]byte, 48)
	response[0] = 0x24
	response[1] = 3
	response[32] = 0xee
	response[40] = 0xee
	if err := validateNTPResponse(response); err != nil {
		t.Fatalf("valid NTP response was rejected: %v", err)
	}
}

func TestHasExactDefaultRouteDoesNotAcceptSubstringMatches(t *testing.T) {
	if !hasExactDefaultRoute("default via 10.10.5.1 dev eth0 proto static\n", "10.10.5.1") {
		t.Fatal("valid default route was not recognised")
	}
	if hasExactDefaultRoute("default via 10.10.5.10 dev eth0\n", "10.10.5.1") {
		t.Fatal("substring route match was accepted")
	}
}

func TestNativeCommandMapsBoundedNetworkOperations(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{name: "namespace", args: []string{"netns", "add", "bt4a-transit"}, want: "ip netns add bt4a-transit"},
		{name: "link", args: []string{"link", "show", "vmbr1"}, want: "ip link show vmbr1"},
		{name: "vlan", args: []string{"vlan", "show", "dev", "bt4a-t-h"}, want: "bridge vlan show dev bt4a-t-h"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path, args := nativeCommand(test.args)
			got := path[strings.LastIndex(path, "/")+1:]
			for _, arg := range args {
				got += " " + arg
			}
			if got != test.want {
				t.Fatalf("nativeCommand(%v) = %q, want %q", test.args, got, test.want)
			}
		})
	}
}

func TestArpingAddressFreeAcceptsNativeNoResponseForms(t *testing.T) {
	if !arpingAddressFree("Sent 2 probes (2 broadcast(s))\nReceived 0 response(s)\n") {
		t.Fatal("native arping no-response output was not treated as a free candidate")
	}
	if !arpingAddressFree("100% packet loss") {
		t.Fatal("packet-loss no-response output was not treated as a free candidate")
	}
	if arpingAddressFree("Received 1 response(s)") {
		t.Fatal("an arping response was treated as a free candidate")
	}
}
