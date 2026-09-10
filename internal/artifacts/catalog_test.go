package artifacts

import "testing"

func TestCatalogMatchesCurrentRuntimeBoundary(t *testing.T) {
	for _, definition := range Definitions() {
		if definition.Name == "airvpn" || definition.Name == "aiops" || definition.Name == "monitoring" || definition.Name == "logging" || definition.Name == "gatus" || definition.Name == "printer" {
			t.Fatalf("retired runtime artifact remains catalogued: %#v", definition)
		}
	}
	for _, name := range []string{"base", "dns", "firewall", "tailnet-router", "bifrost"} {
		if _, ok := Lookup(name); !ok {
			t.Fatalf("current artifact %q is missing", name)
		}
	}
}
