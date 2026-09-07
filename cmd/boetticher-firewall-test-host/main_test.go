package main

import (
	"strings"
	"testing"
)

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
