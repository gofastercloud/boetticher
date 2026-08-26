package opnsense

import (
	"testing"

	"github.com/dave/labinabox/internal/model"
)

func TestBootstrapPlanIsDeterministicAndExplicitlyGated(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	one, err := BootstrapPlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	two, err := BootstrapPlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	if one.ModelRevision != two.ModelRevision || one.Status != "HOLD" {
		t.Fatalf("bootstrap plan is not deterministic or not gated: %#v %#v", one, two)
	}
	if one.WANBridge != "vmbr0" || one.InternalInterface != "vtnet1" || len(one.VLANs) != 4 {
		t.Fatalf("unexpected bootstrap contract: %#v", one)
	}
}
