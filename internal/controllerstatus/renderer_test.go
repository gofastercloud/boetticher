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
	snapshot.VPN = Component{State: Checking}
	snapshot.Tailnet = Component{State: Attention}
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
		t.Fatalf("checking VPN pixel = %#v", frame[3])
	}
	if frame[4].R == 0 || frame[4].G == 0 || frame[4].B != 0 {
		t.Fatalf("attention Tailnet pixel = %#v", frame[4])
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

func TestRendererUsesBlueChaseDuringOperationAndGreenOnCompletion(t *testing.T) {
	renderer := NewRenderer(0.3)
	event := OperationEvent{Event: "operation-progress", Name: "host apply", CurrentStep: 2, TotalSteps: 5}
	frame := renderer.OperationFrame(event, time.Unix(100, 0))
	later := renderer.OperationFrame(event, time.Unix(100, 0).Add(300*time.Millisecond))
	blue := 0
	for _, pixel := range frame {
		if pixel.B > 0 {
			blue++
		}
	}
	if blue < 2 {
		t.Fatalf("operation chase was not blue: %#v", frame)
	}
	different := false
	for index := range frame {
		if frame[index] != later[index] {
			different = true
			break
		}
	}
	if !different {
		t.Fatalf("operation chase did not move: %#v", frame)
	}
	complete := renderer.OperationFrame(OperationEvent{Event: "operation-success", Name: "host apply", CurrentStep: 5, TotalSteps: 5}, time.Unix(100, 0))
	for _, pixel := range complete {
		if pixel.G == 0 || pixel.B != 35 {
			t.Fatalf("completed operation was not green: %#v", complete)
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
	snapshot.VPN = Component{State: Failed, Detail: "VPN status is not healthy"}
	snapshot.DHCPNTP = Component{State: Failed, Detail: "DHCP/NTP capability is unavailable"}
	snapshot.DNS = Component{State: Healthy, Detail: "DNS capability is healthy"}
	snapshot.Tailnet = Component{State: Failed, Detail: "Tailnet capability is unavailable"}
	telemetry := ProxmoxSnapshot{
		Host:      ProxmoxHostStats{Node: "lab-proxmox-01", Version: "pve-manager/9.2.2", CPUPercent: 18, MemoryUsed: 4 << 30, MemoryTotal: 8 << 30, Uptime: 25 * time.Hour},
		Storage:   []StorageStats{{Name: "boetticher-data", Used: 45 << 30, Total: 100 << 30, Percent: 45}},
		Guests:    []GuestStats{{VMID: 201, Name: "pulse", Kind: "lxc", Status: "running"}},
		FetchedAt: time.Now(),
	}
	home := renderer.Render(snapshot, telemetry, nil, StreamDeckHome, 0, -1)
	for index, want := range []string{"PVE", "CPU", "RAM", "DATA", "NET", "CT201", "", "", "", "", "NETWORK", "VPN", "TAILNET", "SCROLL", "REFRESH"} {
		if home[index].Title != want {
			t.Fatalf("home key %d title = %q, want %q", index, home[index].Title, want)
		}
	}
	if home[0].State != Healthy || home[3].State != Healthy || home[4].Value != "812M" || home[5].Title != "CT201" || home[5].Value != "pulse" || home[5].Footer != "RUNNING" || home[5].State != Healthy || home[10].State != Failed || home[11].State != Failed || home[12].State != Failed {
		t.Fatalf("home status keys = %#v %#v %#v %#v %#v %#v", home[0], home[3], home[4], home[5], home[10], home[12])
	}
	host := renderer.Render(snapshot, telemetry, nil, StreamDeckHostDetail, 0, -1)
	if host[0].Title != "NODE" || host[6].Title != "UPDATES" || host[7].Value != "OK" || host[8].Title != "FW" || host[8].State != Healthy || host[9].State != Failed || host[10].Title != "VPN" || host[10].State != Failed || host[11].Title != "TAILNET" || host[11].State != Failed || host[12].Title != "DNS" || host[12].State != Healthy || host[13].Title != "BACK" {
		t.Fatalf("host detail keys = %#v", host)
	}
	guest := renderer.Render(snapshot, telemetry, nil, StreamDeckGuestDetail, 0, 0)
	if guest[0].Title != "CT201" || guest[0].Value != "pulse" || guest[0].Footer != "RUNNING" || guest[1].Value != "pulse" || guest[2].Value != "LXC" || guest[13].Title != "BACK" {
		t.Fatalf("guest detail keys = %#v", guest)
	}
}

func TestNetworkAggregateRequiresAllHealthyAndPreservesUnknown(t *testing.T) {
	snapshot := NewSnapshot(true)
	snapshot.Firewall = Component{State: Healthy}
	snapshot.DNS = Component{State: Healthy}
	snapshot.DHCPNTP = Component{State: Healthy}
	if got := networkComponent(snapshot); got.State != Healthy {
		t.Fatalf("all healthy network aggregate = %#v", got)
	}
	snapshot.DNS = Component{State: Failed}
	if got := networkComponent(snapshot); got.State != Failed {
		t.Fatalf("failed network aggregate = %#v", got)
	}
	snapshot.DNS = Component{Detail: "unknown"}
	if got := networkComponent(snapshot); got.State == Healthy {
		t.Fatalf("unknown network aggregate was healthy: %#v", got)
	}
}

func TestStreamDeckNetworkAndCapabilityDetailNavigation(t *testing.T) {
	snapshot := NewSnapshot(true)
	snapshot.Firewall = Component{State: Healthy, Detail: "firewall healthy"}
	snapshot.DNS = Component{State: Failed, Detail: "DNS unavailable"}
	snapshot.DHCPNTP = Component{State: Healthy, Detail: "DHCP healthy"}
	snapshot.VPN = Component{State: Healthy, Detail: "VPN connected"}
	snapshot.Tailnet = Component{State: Attention, Detail: "authentication required"}
	keys := (StreamDeckRenderer{}).Render(snapshot, ProxmoxSnapshot{}, nil, StreamDeckNetworkDetail, 0, -1)
	if keys[0].Title != "NETWORK" || keys[0].State != Failed || keys[1].Title != "FIREWALL" || keys[2].State != Failed || keys[13].Title != "BACK" {
		t.Fatalf("network detail keys = %#v", keys[:4])
	}
	keys = (StreamDeckRenderer{}).Render(snapshot, ProxmoxSnapshot{}, nil, StreamDeckVPNDetail, 0, -1)
	if keys[0].Title != "VPN" || keys[0].State != Healthy || keys[1].Value != "VPN connected" {
		t.Fatalf("VPN detail keys = %#v", keys[:2])
	}
	d := NewDaemon(DefaultSettings(), nil)
	d.handleStreamDeckEvent(context.Background(), KeyEvent{Index: 10})
	if d.streamdeckView != StreamDeckNetworkDetail {
		t.Fatalf("Network navigation view = %s", d.streamdeckView)
	}
	d.handleStreamDeckEvent(context.Background(), KeyEvent{Index: 13})
	d.handleStreamDeckEvent(context.Background(), KeyEvent{Index: 11})
	if d.streamdeckView != StreamDeckVPNDetail {
		t.Fatalf("VPN navigation view = %s", d.streamdeckView)
	}
}

func TestStreamDeckMarqueeMovesLongHostnamesWithoutShrinkingGlyphs(t *testing.T) {
	if !needsDeckMarquee("a-very-long-managed-hostname") {
		t.Fatal("long hostname did not require marquee")
	}
	first := marqueeDeckText(streamDeckFont, "a-very-long-managed-hostname", streamDeckTextWidth, time.UnixMilli(0))
	second := marqueeDeckText(streamDeckFont, "a-very-long-managed-hostname", streamDeckTextWidth, time.UnixMilli(750))
	if first == second {
		t.Fatalf("hostname marquee did not advance: %q", first)
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
	if keys[5].Title != "VM201" || keys[5].Value != "guest" || keys[6].State != Off || keys[7].State != Attention || keys[13].Value != "1/2" {
		t.Fatalf("first guest page = %#v", keys[5:14])
	}
	keys = (StreamDeckRenderer{}).Render(NewSnapshot(true), telemetry, nil, StreamDeckHome, 1, -1)
	if keys[5].Title != "VM206" || keys[8].Title != "VM209" || keys[9].Title != "" || keys[13].Value != "2/2" {
		t.Fatalf("second guest page = %#v", keys[5:14])
	}
	telemetry.Stale = true
	keys = (StreamDeckRenderer{}).Render(NewSnapshot(true), telemetry, nil, StreamDeckHome, 0, -1)
	if keys[1].State != Attention || keys[2].Footer != "STALE" || keys[3].State != Attention {
		t.Fatalf("stale telemetry keys = %#v %#v %#v", keys[1], keys[2], keys[3])
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
	d.telemetry.Guests = []GuestStats{{VMID: 201, Name: "pulse", Kind: "lxc", Status: "running"}, {VMID: 202, Name: "one", Kind: "vm", Status: "running"}, {VMID: 203, Name: "two", Kind: "vm", Status: "running"}, {VMID: 204, Name: "three", Kind: "vm", Status: "running"}, {VMID: 205, Name: "four", Kind: "vm", Status: "running"}, {VMID: 206, Name: "five", Kind: "vm", Status: "running"}}
	d.Now = func() time.Time { return time.Unix(100, 0) }
	d.handleStreamDeckEvent(context.Background(), KeyEvent{Index: 0})
	if d.streamdeckView != StreamDeckHostDetail {
		t.Fatalf("Host key view = %s", d.streamdeckView)
	}
	d.handleStreamDeckEvent(context.Background(), KeyEvent{Index: 13})
	if d.streamdeckView != StreamDeckHome {
		t.Fatalf("Back key view = %s", d.streamdeckView)
	}
	d.handleStreamDeckEvent(context.Background(), KeyEvent{Index: 13})
	if d.streamdeckPage != 1 {
		t.Fatalf("Scroll key page = %d, want 1", d.streamdeckPage)
	}
	d.handleStreamDeckEvent(context.Background(), KeyEvent{Index: 5})
	if d.streamdeckView != StreamDeckGuestDetail || d.streamdeckGuest != 5 {
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
	for _, component := range []Component{snapshot.Firewall, snapshot.Tailnet, snapshot.DHCPNTP, snapshot.Host} {
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

func TestSuccessfulOperationShowsTerminalFrameBeforeReturningToStatusStack(t *testing.T) {
	d := NewDaemon(DefaultSettings(), nil)
	now := time.Unix(100, 0)
	d.Now = func() time.Time { return now }
	d.handleEvent(OperationEvent{Event: "operation-start", Name: "firewall apply", Steps: 7})
	if d.operation == nil {
		t.Fatal("operation did not start")
	}
	d.handleEvent(OperationEvent{Event: "operation-success", Name: "firewall apply"})
	if d.operation == nil {
		t.Fatal("successful operation did not retain its terminal frame")
	}
	now = now.Add(4 * time.Second)
	d.render(context.Background())
	if d.operation != nil {
		t.Fatalf("expired operation retained an overlay: %#v", d.operation)
	}
}

func TestRendererUsesTestingPixelsForNamedResults(t *testing.T) {
	renderer := NewRenderer(0.3)
	event := OperationEvent{Event: "operation-progress", Mode: Testing, Tests: []TestResult{
		{Name: "one", State: Checking}, {Name: "two", State: Healthy}, {Name: "three", State: Failed},
	}}
	frame := renderer.OperationFrame(event, time.UnixMilli(0))
	if frame[0].B == 0 || frame[0].R != 0 || frame[0].G == 0 {
		t.Fatalf("active test was not blue: %#v", frame[0])
	}
	if frame[1].G == 0 || frame[1].R != 0 {
		t.Fatalf("passed test was not solid green: %#v", frame[1])
	}
	if frame[2].R == 0 || frame[2].G != 0 {
		t.Fatalf("failed test was not solid red: %#v", frame[2])
	}
	later := renderer.OperationFrame(event, time.UnixMilli(175))
	if frame[0].Brightness == later[0].Brightness {
		t.Fatalf("active test did not pulse: start=%d later=%d", frame[0].Brightness, later[0].Brightness)
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
