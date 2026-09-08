package firewallmodule

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/openwrt"
)

type applianceFake struct {
	ops        []string
	current    map[string]map[string]openwrt.UCISection
	failCommit string
}

func (f *applianceFake) ReloadFirewall(_ context.Context) error {
	f.ops = append(f.ops, "reload:firewall")
	return nil
}

func (f *applianceFake) UCIGet(_ context.Context, packageName string) (map[string]openwrt.UCISection, error) {
	f.ops = append(f.ops, "get:"+packageName)
	return f.current[packageName], nil
}
func (f *applianceFake) UCICommit(_ context.Context, packageName string) error {
	f.ops = append(f.ops, "commit:"+packageName)
	if packageName == f.failCommit {
		return errors.New("commit failed")
	}
	return nil
}
func (f *applianceFake) ServiceConfigChange(_ context.Context, packageName string) error {
	f.ops = append(f.ops, "event:"+packageName)
	return nil
}
func (f *applianceFake) UCIAddNamed(_ context.Context, _, typ, name string) (string, error) {
	f.ops = append(f.ops, "add:"+typ+":"+name)
	return name, nil
}
func (f *applianceFake) UCISet(_ context.Context, _, section, option, value string) error {
	f.ops = append(f.ops, "set:"+section+":"+option+":"+value)
	return nil
}
func (f *applianceFake) UCISetList(_ context.Context, _, section, option string, values []string) error {
	f.ops = append(f.ops, "list:"+section+":"+option+":"+strings.Join(values, ","))
	return nil
}
func (f *applianceFake) UCIDelete(_ context.Context, _, section, option string) error {
	f.ops = append(f.ops, "delete:"+section+":"+option)
	return nil
}
func (f *applianceFake) UCIApply(context.Context, int) error {
	f.ops = append(f.ops, "apply")
	return nil
}

func TestReconcileApplianceSafetyFailurePreventsNetworkAndServices(t *testing.T) {
	composition, err := ComposeAppliance(testCompositionSite(), compositionModules(false), nil)
	if err != nil {
		t.Fatal(err)
	}
	fake := &applianceFake{current: map[string]map[string]openwrt.UCISection{"firewall": {"defaults": {Type: "defaults", Options: map[string]string{"auto_includes": "1", "flow_offloading": "0", "flow_offloading_hw": "0"}}}}}
	_, err = ReconcileAppliance(context.Background(), fake, composition, ApplianceVerifyCallbacks{SafetyBeforeNetwork: func(context.Context) error { return errors.New("unsafe") }, NetworkReady: func(context.Context) error { return nil }, SafetyAfterNetwork: func(context.Context) error { return nil }})
	if err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("error = %v", err)
	}
	for _, op := range fake.ops {
		if strings.HasPrefix(op, "add:") && strings.Contains(op, "boetticher_iface_") {
			t.Fatalf("network staged before safety: %v", fake.ops)
		}
	}
}

func TestReconcileApplianceNoopRunsGatesWithoutWrites(t *testing.T) {
	composition, err := ComposeAppliance(testCompositionSite(), compositionModules(false), nil)
	if err != nil {
		t.Fatal(err)
	}
	current := map[string]map[string]openwrt.UCISection{}
	for _, item := range []struct {
		name     string
		sections []Section
	}{{"firewall", composition.Firewall}, {"network", composition.Network}, {"system", composition.System}, {"stubby", composition.Stubby}, {"dhcp", composition.DHCP}} {
		current[item.name] = map[string]openwrt.UCISection{}
		for _, s := range item.sections {
			current[item.name][s.Name] = openwrt.UCISection{Type: s.Type, Options: s.Options, Lists: s.Lists}
		}
	}
	current["firewall"]["defaults"] = openwrt.UCISection{Type: "defaults", Options: map[string]string{"auto_includes": "1", "flow_offloading": "0", "flow_offloading_hw": "0"}}
	fake := &applianceFake{current: current}
	gates := 0
	changed, err := ReconcileAppliance(context.Background(), fake, composition, ApplianceVerifyCallbacks{SafetyBeforeNetwork: func(context.Context) error { gates++; return nil }, NetworkReady: func(context.Context) error { gates++; return nil }, SafetyAfterNetwork: func(context.Context) error { gates++; return nil }})
	if err != nil || changed != 0 || len(fake.ops) != 5 {
		t.Fatalf("noop = changed:%d err:%v ops:%v", changed, err, fake.ops)
	}
	if gates != 3 {
		t.Fatalf("gates = %d", gates)
	}
}

func testCompositionSite() model.Site {
	return model.NewSite("lab", "controller-local", model.GatewayModeManaged)
}
