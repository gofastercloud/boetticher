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
	snapshot.Host = Component{State: Failed}
	snapshot.Firewall = Component{State: Off}
	snapshot.DHCPNTP = Component{State: Checking}
	snapshot.DNS = Component{State: Attention}
	snapshot.Internet.Component = Component{State: Healthy}
	snapshot.ControllerUpdates = Component{State: Attention}
	snapshot.HostUpdates = Component{State: Checking}
	frame := renderer.Frame(snapshot, time.Unix(100, 0))
	if len(frame) != PixelCount {
		t.Fatalf("frame has %d pixels", len(frame))
	}
	if frame[0].G == 0 || frame[0].B != 35 {
		t.Fatalf("healthy Controller pixel = %#v", frame[0])
	}
	if frame[1].R == 0 || frame[1].G != 0 {
		t.Fatalf("failed Host pixel = %#v", frame[1])
	}
	if frame[2] != (Pixel{}) {
		t.Fatalf("off firewall pixel = %#v", frame[2])
	}
	if frame[3].B == 0 || frame[3].G == 0 {
		t.Fatalf("checking DHCP/NTP pixel = %#v", frame[3])
	}
	if frame[4].R == 0 || frame[4].G == 0 || frame[4].B != 0 {
		t.Fatalf("attention DNS pixel = %#v", frame[4])
	}
	if frame[5].G == 0 || frame[5].B != 35 {
		t.Fatalf("healthy Internet pixel = %#v", frame[5])
	}
	if frame[6].R == 0 || frame[6].G == 0 || frame[6].B != 0 {
		t.Fatalf("attention Controller update pixel = %#v", frame[6])
	}
	if frame[7].B == 0 || frame[7].G == 0 {
		t.Fatalf("checking Host update pixel = %#v", frame[7])
	}
}

func TestRendererUsesOperationProgressInsteadOfDashboard(t *testing.T) {
	renderer := NewRenderer(0.3)
	frame := renderer.OperationFrame(OperationEvent{Event: "operation-progress", Name: "host apply", CurrentStep: 2, TotalSteps: 5}, time.Unix(100, 0))
	if frame[0].G == 0 || frame[1].G == 0 || frame[2].G == 0 {
		t.Fatalf("completed pixels were not green: %#v", frame[:3])
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

func TestRendererUsesStateSpecificLightEffects(t *testing.T) {
	renderer := NewRenderer(0.3)
	greenAtStart := renderer.componentPixel(Healthy, time.Unix(0, 0), 0)
	greenAtPeak := renderer.componentPixel(Healthy, time.UnixMilli(750), 0)
	if greenAtStart.Brightness == greenAtPeak.Brightness {
		t.Fatalf("green is not breathing: start=%d peak=%d", greenAtStart.Brightness, greenAtPeak.Brightness)
	}
	amberAtStart := renderer.componentPixel(Attention, time.Unix(0, 0), 0)
	amberAtPeak := renderer.componentPixel(Attention, time.UnixMilli(300), 0)
	if amberAtStart.Brightness == amberAtPeak.Brightness {
		t.Fatalf("amber is not pulsing: start=%d peak=%d", amberAtStart.Brightness, amberAtPeak.Brightness)
	}
	blueAtStart := renderer.componentPixel(Checking, time.Unix(0, 0), 0)
	blueLater := renderer.componentPixel(Checking, time.UnixMilli(750), 0)
	if blueAtStart.Brightness != renderer.MaxBrightness || blueAtStart.Brightness != blueLater.Brightness {
		t.Fatalf("blue is not steady: start=%d later=%d max=%d", blueAtStart.Brightness, blueLater.Brightness, renderer.MaxBrightness)
	}
	redOn := renderer.componentPixel(Failed, time.Unix(0, 0), 0)
	redOff := renderer.componentPixel(Failed, time.UnixMilli(400), 0)
	if redOn.Brightness == 0 || redOff.Brightness != 0 {
		t.Fatalf("red is not flashing: on=%d off=%d", redOn.Brightness, redOff.Brightness)
	}
}

func TestStreamDeckRendererBuildsHomeAndDetailViews(t *testing.T) {
	renderer := StreamDeckRenderer{}
	snapshot := NewSnapshot(true)
	snapshot.Controller = Component{State: Healthy}
	snapshot.Host = Component{State: Healthy}
	snapshot.Internet = InternetStatus{Component: Component{State: Healthy}, ThroughputMbps: 812, ThroughputAt: time.Now()}
	snapshot.HostUpdates = Component{State: Attention, Detail: "Proxmox Host updates available"}
	snapshot.Firewall = Component{State: Healthy, Detail: "firewall provider is running"}
	snapshot.DHCPNTP = Component{State: Failed, Detail: "DHCP/DDNS/NTP capability is not implemented"}
	snapshot.DNS = Component{State: Failed, Detail: "DNS capability is not implemented"}
	telemetry := ProxmoxSnapshot{
		Host:      ProxmoxHostStats{Node: "lab-proxmox-01", Version: "pve-manager/9.2.2", CPUPercent: 18, MemoryUsed: 4 << 30, MemoryTotal: 8 << 30, Uptime: 25 * time.Hour},
		Storage:   []StorageStats{{Name: "boetticher-data", Used: 45 << 30, Total: 100 << 30, Percent: 45}},
		Guests:    []GuestStats{{VMID: 201, Name: "pulse", Kind: "lxc", Status: "running"}},
		FetchedAt: time.Now(),
	}
	home := renderer.Render(snapshot, telemetry, nil, StreamDeckHome, 0, -1)
	for index, want := range []string{"PVE", "CPU", "RAM", "DATA", "NET", "201 pulse", "", "", "", "", "", "", "", "PAGE", "REFRESH"} {
		if home[index].Title != want {
			t.Fatalf("home key %d title = %q, want %q", index, home[index].Title, want)
		}
	}
	if home[0].State != Healthy || home[4].Value != "812M" || home[5].State != Healthy {
		t.Fatalf("home status keys = %#v %#v %#v", home[0], home[4], home[5])
	}
	host := renderer.Render(snapshot, telemetry, nil, StreamDeckHostDetail, 0, -1)
	if host[0].Title != "NODE" || host[6].Title != "UPDATES" || host[7].Value != "OK" || host[8].Title != "FW" || host[8].State != Healthy || host[9].State != Failed || host[10].State != Failed || host[13].Title != "BACK" {
		t.Fatalf("host detail keys = %#v", host)
	}
	guest := renderer.Render(snapshot, telemetry, nil, StreamDeckGuestDetail, 0, 0)
	if guest[0].Value != "201" || guest[1].Value != "pulse" || guest[2].Value != "LXC" || guest[13].Title != "BACK" {
		t.Fatalf("guest detail keys = %#v", guest)
	}
}

func TestStreamDeckRendererPagesGuestsAndKeepsStoppedNeutral(t *testing.T) {
	guests := make([]GuestStats, 9)
	for index := range guests {
		guests[index] = GuestStats{VMID: 201 + index, Name: "guest", Kind: "vm", Status: "running"}
	}
	guests[1].Status = "stopped"
	guests[2].Status = "unknown"
	telemetry := ProxmoxSnapshot{Guests: guests, FetchedAt: time.Now()}
	keys := (StreamDeckRenderer{}).Render(NewSnapshot(true), telemetry, nil, StreamDeckHome, 0, -1)
	if keys[5].Value != "VM" || keys[6].State != Off || keys[7].State != Attention || keys[13].Value != "1/2" {
		t.Fatalf("first guest page = %#v", keys[5:14])
	}
	keys = (StreamDeckRenderer{}).Render(NewSnapshot(true), telemetry, nil, StreamDeckHome, 1, -1)
	if keys[5].Title != "209 guest" || keys[6].Title != "" || keys[13].Value != "2/2" {
		t.Fatalf("second guest page = %#v", keys[5:14])
	}
	telemetry.Stale = true
	keys = (StreamDeckRenderer{}).Render(NewSnapshot(true), telemetry, nil, StreamDeckHome, 0, -1)
	if keys[1].State != Attention || keys[2].Footer != "STALE" {
		t.Fatalf("stale telemetry keys = %#v %#v", keys[1], keys[2])
	}
}

func TestDaemonRetainsLastGoodTelemetryWhenCollectionFails(t *testing.T) {
	d := NewDaemon(DefaultSettings(), nil)
	d.applyTelemetry(telemetryResult{snapshot: ProxmoxSnapshot{Host: ProxmoxHostStats{Node: "pve"}, FetchedAt: time.Unix(100, 0)}})
	d.applyTelemetry(telemetryResult{err: errors.New("Host unavailable")})
	if d.telemetry.Host.Node != "pve" || !d.telemetry.Stale || d.telemetry.Error != "Host unavailable" {
		t.Fatalf("stale telemetry = %#v", d.telemetry)
	}
}

func TestStreamDeckNavigationIsReadOnlyAndRefreshIsRateLimited(t *testing.T) {
	d := NewDaemon(DefaultSettings(), nil)
	d.telemetry.Guests = []GuestStats{{VMID: 201, Name: "pulse", Kind: "lxc", Status: "running"}}
	d.Now = func() time.Time { return time.Unix(100, 0) }
	d.handleStreamDeckEvent(context.Background(), KeyEvent{Index: 0})
	if d.streamdeckView != StreamDeckHostDetail {
		t.Fatalf("Host key view = %s", d.streamdeckView)
	}
	d.handleStreamDeckEvent(context.Background(), KeyEvent{Index: 13})
	if d.streamdeckView != StreamDeckHome {
		t.Fatalf("Back key view = %s", d.streamdeckView)
	}
	d.handleStreamDeckEvent(context.Background(), KeyEvent{Index: 5})
	if d.streamdeckView != StreamDeckGuestDetail || d.streamdeckGuest != 0 {
		t.Fatalf("guest key view=%s guest=%d", d.streamdeckView, d.streamdeckGuest)
	}
	d.handleStreamDeckEvent(context.Background(), KeyEvent{Index: 13})
	d.Telemetry = func(context.Context) (ProxmoxSnapshot, error) { return ProxmoxSnapshot{}, nil }
	d.handleStreamDeckEvent(context.Background(), KeyEvent{Index: 14})
	if d.manualRefreshAt.IsZero() {
		t.Fatal("refresh key did not request telemetry")
	}
	first := d.manualRefreshAt
	d.handleStreamDeckEvent(context.Background(), KeyEvent{Index: 14})
	if !d.manualRefreshAt.Equal(first) {
		t.Fatal("refresh key bypassed rate limit")
	}
	d.handleStreamDeckEvent(context.Background(), KeyEvent{Index: -1})
	d.handleStreamDeckEvent(context.Background(), KeyEvent{Index: StreamDeckKeyCount})
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
	for _, component := range []Component{snapshot.Firewall, snapshot.DNS, snapshot.DHCPNTP, snapshot.Host} {
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

func TestControllerConfigStagedUsesBlueUpdateState(t *testing.T) {
	d := NewDaemon(DefaultSettings(), nil)
	d.handleEvent(OperationEvent{Event: "configuration-staged", Name: "controller config", Staged: true})
	if d.snapshot.ControllerUpdates.State != Checking {
		t.Fatalf("controller updates after staged config = %#v", d.snapshot.ControllerUpdates)
	}
	d.handleEvent(OperationEvent{Event: "configuration-applied", Name: "controller config"})
	if d.configStaged {
		t.Fatal("staged Controller config was not cleared")
	}
}

func TestDaemonSeparatesMinutePingsFromHourlySpeedtests(t *testing.T) {
	settings := DefaultSettings()
	settings.PingInterval = time.Minute
	settings.ThroughputInterval = time.Hour
	d := NewDaemon(settings, nil)
	now := time.Unix(100, 0)
	pings := 0
	speedtests := 0
	d.Now = func() time.Time { return now }
	d.Controller = func(context.Context) CheckResult {
		return CheckResult{Configured: true, Healthy: true, Update: Component{State: Healthy}}
	}
	d.Host = func(context.Context) CheckResult { return CheckResult{} }
	d.Connectivity = func(context.Context) CheckResult {
		pings++
		return CheckResult{Configured: true, Healthy: true}
	}
	d.Throughput = func(context.Context) (float64, error) {
		speedtests++
		return 600, nil
	}
	d.refreshAt(context.Background(), now)
	now = now.Add(30 * time.Second)
	d.refreshAt(context.Background(), now)
	if pings != 1 || speedtests != 1 {
		t.Fatalf("30-second refresh counts = ping %d speedtest %d", pings, speedtests)
	}
	now = now.Add(30 * time.Second)
	d.refreshAt(context.Background(), now)
	if pings != 2 || speedtests != 1 {
		t.Fatalf("60-second refresh counts = ping %d speedtest %d", pings, speedtests)
	}
	now = now.Add(time.Hour)
	d.refreshAt(context.Background(), now)
	if pings != 3 || speedtests != 2 {
		t.Fatalf("hourly refresh counts = ping %d speedtest %d", pings, speedtests)
	}
}
