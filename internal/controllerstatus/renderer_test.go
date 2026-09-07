package controllerstatus

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeDriver struct {
	frames []([]Pixel)
	err    error
}

func (f *fakeDriver) Show(_ context.Context, frame []Pixel) error {
	if f.err != nil {
		return f.err
	}
	f.frames = append(f.frames, append([]Pixel(nil), frame...))
	return nil
}
func (f *fakeDriver) Clear(_ context.Context) error { return nil }
func (f *fakeDriver) Close() error                  { return nil }

func TestRendererMapsFixedStatesToColours(t *testing.T) {
	renderer := NewRenderer(0.3)
	snapshot := NewSnapshot(false)
	snapshot.Controller = Component{State: Healthy}
	snapshot.Host = Component{State: Checking}
	snapshot.Firewall = Component{State: Attention}
	snapshot.DNS = Component{State: Failed}
	snapshot.DHCP = Component{State: Off}
	snapshot.Internet.Component = Component{State: Healthy}
	snapshot.Configuration = Component{State: Checking}
	snapshot.RebootRequired = Component{State: Attention}
	frame := renderer.Frame(snapshot, time.Unix(100, 0))
	if len(frame) != PixelCount {
		t.Fatalf("frame has %d pixels", len(frame))
	}
	if frame[0].G == 0 || frame[0].B != 35 {
		t.Fatalf("healthy pixel = %#v", frame[0])
	}
	if frame[1].B == 0 || frame[1].G == 0 {
		t.Fatalf("checking pixel = %#v", frame[1])
	}
	if frame[2].R == 0 || frame[2].G == 0 || frame[2].B != 0 {
		t.Fatalf("attention pixel = %#v", frame[2])
	}
	if frame[3].R == 0 || frame[3].G != 0 {
		t.Fatalf("failed pixel = %#v", frame[3])
	}
	if frame[4] != (Pixel{}) {
		t.Fatalf("off pixel = %#v", frame[4])
	}
}

func TestRendererUsesOperationProgressInsteadOfDashboard(t *testing.T) {
	renderer := NewRenderer(0.3)
	frame := renderer.OperationFrame(OperationEvent{Event: "operation-progress", Name: "host apply", CurrentStep: 2, TotalSteps: 5}, time.Unix(100, 0))
	if frame[0].G == 0 || frame[1].G == 0 {
		t.Fatalf("completed pixels were not green: %#v", frame[:2])
	}
	if frame[3].B == 0 {
		t.Fatalf("current pixel was not blue: %#v", frame[3])
	}
	for _, pixel := range frame[4:] {
		if pixel != (Pixel{}) {
			t.Fatalf("future pixel was not off: %#v", pixel)
		}
	}
}

func TestDaemonDisablesFailedDriverWithoutReturningHardwareError(t *testing.T) {
	driver := &fakeDriver{err: errors.New("GPIO disappeared")}
	daemon := NewDaemon(DefaultSettings(), driver)
	daemon.render(context.Background())
	if !daemon.driverBroken {
		t.Fatal("failed Blinkt driver was not isolated")
	}
}

func TestNewSnapshotLeavesUnconfiguredCapabilitiesOff(t *testing.T) {
	snapshot := NewSnapshot(false)
	for _, component := range []Component{snapshot.Firewall, snapshot.DNS, snapshot.DHCP, snapshot.Host} {
		if component.State != Off {
			t.Fatalf("unconfigured component = %#v, want off", component)
		}
	}
}

func TestDebouncerRequiresTwoFailuresAndOneRecovery(t *testing.T) {
	debouncer := NewDebouncer(Healthy)
	if result := debouncer.Update(false, "transient"); result.State != Checking {
		t.Fatalf("first failed poll = %#v, want checking", result)
	}
	if result := debouncer.Update(false, "persistent"); result.State != Failed {
		t.Fatalf("second failed poll = %#v, want failed", result)
	}
	if result := debouncer.Update(true, "recovered"); result.State != Healthy {
		t.Fatalf("successful recovery = %#v, want healthy", result)
	}
}

func TestOperationFailureMarksConfigurationImmediately(t *testing.T) {
	d := NewDaemon(DefaultSettings(), nil)
	d.handleEvent(OperationEvent{Event: "operation-start", Name: "host apply", Steps: 5})
	d.handleEvent(OperationEvent{Event: "operation-failure", Name: "host apply", Detail: "storage failed", ConfigurationFailed: true})
	if d.snapshot.Configuration.State != Failed {
		t.Fatalf("configuration after failed operation = %#v", d.snapshot.Configuration)
	}
	d.handleEvent(OperationEvent{Event: "operation-success", Name: "host apply"})
	if d.snapshot.Configuration.State != Off {
		t.Fatalf("configuration after successful operation = %#v", d.snapshot.Configuration)
	}
}
