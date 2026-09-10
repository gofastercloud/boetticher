package firewallmodule

import "testing"

func TestManagedSystemRuleRequiresEncodedIdentity(t *testing.T) {
	options := map[string]string{"name": "Boetticher system example trusted", "src": "trusted", "dest": "servers", "proto": "tcp", "family": "ipv4", "target": "ACCEPT", "dest_ip": "192.0.2.20", "dest_port": "8080"}
	if !managedRuleIdentity("boetticher_system_example_trusted", options) {
		t.Fatal("valid encoded system rule rejected")
	}
	if managedRuleIdentity("boetticher_system_foreign_trusted", options) {
		t.Fatal("foreign lookalike system rule accepted")
	}
}
