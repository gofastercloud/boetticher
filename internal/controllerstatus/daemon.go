package controllerstatus

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Daemon struct {
	Settings          Settings
	Driver            Driver
	Logger            *log.Logger
	Controller        func(context.Context) CheckResult
	Host              func(context.Context) CheckResult
	Modules           func(context.Context) ModuleStatus
	Connectivity      func(context.Context) CheckResult
	Throughput        func(context.Context) (float64, error)
	Telemetry         func(context.Context) (ProxmoxSnapshot, error)
	StreamDeckFactory StreamDeckFactory
	Now               func() time.Time

	renderer              Renderer
	snapshot              StatusSnapshot
	controller            *Debouncer
	host                  *Debouncer
	firewall              *Debouncer
	internet              *Debouncer
	throughput            float64
	throughputAt          time.Time
	throughputTry         time.Time
	connectivityAt        time.Time
	lastConnectivity      CheckResult
	telemetry             ProxmoxSnapshot
	telemetryAttempt      time.Time
	telemetryRunning      bool
	telemetryResults      chan telemetryResult
	operation             *operationDisplay
	configStaged          bool
	streamdeckFrames      chan []KeyImage
	streamdeckEvents      chan KeyEvent
	refreshResults        chan refreshResult
	refreshRunning        bool
	refreshCancel         context.CancelFunc
	throughputResults     chan throughputResult
	throughputRunning     bool
	skipThroughput        bool
	streamdeckView        StreamDeckView
	streamdeckPage        int
	streamdeckGuest       int
	streamdeckAnimationAt time.Time
	manualRefreshAt       time.Time
	streamdeckDirty       bool
	previous              StatusSnapshot
	driverBroken          bool
}

type operationDisplay struct {
	event  OperationEvent
	result State
	until  time.Time
}

type telemetryResult struct {
	snapshot ProxmoxSnapshot
	err      error
}

type refreshResult struct {
	snapshot         StatusSnapshot
	connectivityAt   time.Time
	lastConnectivity CheckResult
	throughput       float64
	throughputAt     time.Time
	throughputTry    time.Time
}

type throughputResult struct {
	value float64
	err   error
	at    time.Time
}

// Module status is a bounded but multi-hop observation: DHCP, DNS, and the
// firewall status commands each perform their own authenticated provider or
// Host checks. Keep the shorter budget for local Controller/Host checks, but
// do not turn normal sequential module observations into false failures.
// Module status invokes five authenticated, multi-hop native commands in
// sequence. Keep enough bounded time for the slowest measured lab round while
// still preventing a hung provider from blocking the status daemon forever.
const moduleCheckTimeout = 45 * time.Second

func NewDaemon(settings Settings, driver Driver) *Daemon {
	if settings.Interval <= 0 {
		settings.Interval = DefaultInterval
	}
	if settings.ThroughputInterval <= 0 {
		settings.ThroughputInterval = DefaultThroughputPeriod
	}
	if settings.PingInterval <= 0 {
		settings.PingInterval = DefaultPingPeriod
	}
	if settings.TelemetryInterval <= 0 {
		settings.TelemetryInterval = DefaultTelemetryPeriod
	}
	if settings.HealthyMbps <= 0 {
		settings.HealthyMbps = DefaultHealthyMbps
	}
	if settings.SocketPath == "" {
		settings.SocketPath = DefaultSocketPath
	}
	return &Daemon{
		Settings:          settings,
		Driver:            driver,
		Logger:            log.New(io.Discard, "", 0),
		Now:               time.Now,
		renderer:          NewRenderer(settings.Brightness),
		controller:        NewDebouncer(Checking),
		host:              NewDebouncer(Checking),
		firewall:          NewDebouncer(Checking),
		internet:          NewDebouncer(Checking),
		telemetryResults:  make(chan telemetryResult, 1),
		refreshResults:    make(chan refreshResult, 1),
		throughputResults: make(chan throughputResult, 1),
		streamdeckFrames:  make(chan []KeyImage, 1),
		streamdeckEvents:  make(chan KeyEvent, 16),
		streamdeckView:    StreamDeckHome,
		streamdeckGuest:   -1,
		streamdeckDirty:   true,
		snapshot:          NewSnapshot(false),
	}
}

func (d *Daemon) Run(ctx context.Context) error {
	if d.Logger == nil {
		d.Logger = log.New(io.Discard, "", 0)
	}
	if d.Controller == nil {
		d.Controller = ControllerChecker{ConfigPath: d.Settings.ConfigPath, RebootRequiredPath: d.Settings.RebootRequiredPath}.Check
	}
	if d.Host == nil {
		d.Host = HostChecker{}.Check
	}
	if d.Modules == nil {
		d.Modules = (ModuleChecker{}).Check
	}
	if d.Connectivity == nil {
		d.Connectivity = (HostConnectivityChecker{}).Check
	}
	if d.Throughput == nil {
		d.Throughput = func(ctx context.Context) (float64, error) {
			return (HostSpeedtestChecker{}).Sample(ctx)
		}
	}
	if d.Settings.StreamDeckEnabled {
		if d.Telemetry == nil {
			d.Telemetry = (ProxmoxCollector{}).Collect
		}
		if d.StreamDeckFactory == nil {
			d.StreamDeckFactory = NewNativeStreamDeckFactory(StreamDeckConfig{Serial: d.Settings.StreamDeckSerial}, d.Settings.StreamDeckBrightness)
		}
		go runStreamDeck(ctx, d.StreamDeckFactory, d.streamdeckFrames, d.streamdeckEvents, d.Logger)
	}
	var telemetryTicker *time.Ticker
	if d.Settings.StreamDeckEnabled {
		telemetryTicker = time.NewTicker(d.Settings.TelemetryInterval)
		defer telemetryTicker.Stop()
	}
	_, cleanup, events, err := listen(ctx, d.Settings.SocketPath)
	if err != nil {
		return err
	}
	defer cleanup()
	streamDeckState := "disabled"
	if d.Settings.StreamDeckEnabled {
		streamDeckState = "enabled"
	}
	d.Logger.Printf("status daemon started; polling every %s; StreamDeck %s; telemetry every %s", d.Settings.Interval, streamDeckState, d.Settings.TelemetryInterval)
	d.startup(ctx)
	d.scheduleRefresh(ctx, d.Now())
	d.render(ctx)
	ticker := time.NewTicker(d.Settings.Interval)
	defer ticker.Stop()
	frameTicker := time.NewTicker(100 * time.Millisecond)
	defer frameTicker.Stop()
	var telemetryTicks <-chan time.Time
	if telemetryTicker != nil {
		telemetryTicks = telemetryTicker.C
	}
	for {
		select {
		case <-ctx.Done():
			if d.refreshCancel != nil {
				d.refreshCancel()
			}
			d.shutdown(ctx)
			return nil
		case event := <-events:
			d.handleEvent(event)
			d.render(ctx)
		case event := <-d.streamdeckEvents:
			d.handleStreamDeckEvent(ctx, event)
			d.render(ctx)
		case result := <-d.telemetryResults:
			d.applyTelemetry(result)
			d.render(ctx)
		case result := <-d.refreshResults:
			d.applyRefreshResult(result)
			d.scheduleThroughput(ctx, d.Now())
			d.render(ctx)
		case result := <-d.throughputResults:
			d.applyThroughputResult(result)
			d.render(ctx)
			d.render(ctx)
		case now := <-telemetryTicks:
			d.scheduleTelemetry(ctx, now)
			d.render(ctx)
		case now := <-ticker.C:
			d.scheduleRefresh(ctx, now)
			d.scheduleThroughput(ctx, now)
			d.render(ctx)
		case <-frameTicker.C:
			d.render(ctx)
		}
	}
}

func (d *Daemon) refresh(ctx context.Context) {
	d.refreshAt(ctx, d.Now())
}

func (d *Daemon) scheduleRefresh(ctx context.Context, now time.Time) {
	if d.refreshRunning {
		return
	}
	d.refreshRunning = true
	checkCtx, cancel := context.WithCancel(ctx)
	d.refreshCancel = cancel
	worker := *d
	worker.snapshot = d.snapshot
	worker.previous = d.previous
	worker.skipThroughput = true
	worker.Telemetry = nil
	go func() {
		worker.refreshAt(checkCtx, now)
		cancel()
		result := refreshResult{
			snapshot: worker.snapshot, connectivityAt: worker.connectivityAt,
			lastConnectivity: worker.lastConnectivity, throughput: worker.throughput,
			throughputAt: worker.throughputAt, throughputTry: worker.throughputTry,
		}
		select {
		case d.refreshResults <- result:
		case <-ctx.Done():
		}
	}()
}

func (d *Daemon) applyRefreshResult(result refreshResult) {
	d.refreshRunning = false
	d.refreshCancel = nil
	d.snapshot = result.snapshot
	d.connectivityAt = result.connectivityAt
	d.lastConnectivity = result.lastConnectivity
	d.streamdeckDirty = true
	d.logTransitions()
}

func (d *Daemon) scheduleThroughput(ctx context.Context, now time.Time) {
	if d.Throughput == nil || d.throughputRunning || !d.lastConnectivity.Healthy {
		return
	}
	if !d.throughputTry.IsZero() && now.Sub(d.throughputTry) < d.Settings.ThroughputInterval {
		return
	}
	d.throughputTry = now
	d.throughputRunning = true
	go func() {
		checkCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		value, err := d.Throughput(checkCtx)
		cancel()
		select {
		case d.throughputResults <- throughputResult{value: value, err: err, at: now}:
		case <-ctx.Done():
		}
	}()
}

func (d *Daemon) applyThroughputResult(result throughputResult) {
	d.throughputRunning = false
	if result.err != nil {
		d.Logger.Printf("throughput sample failed: %v", result.err)
	} else if result.value >= 0 {
		d.throughput, d.throughputAt = result.value, result.at
	}
	d.snapshot.Internet.ThroughputMbps = d.throughput
	d.snapshot.Internet.ThroughputAt = d.throughputAt
	d.streamdeckDirty = true
}

func (d *Daemon) refreshAt(ctx context.Context, now time.Time) {
	type result struct {
		kind    string
		data    CheckResult
		modules ModuleStatus
	}
	runConnectivity := d.connectivityAt.IsZero() || now.Sub(d.connectivityAt) >= d.Settings.PingInterval
	checks := []struct {
		kind string
		fn   func(context.Context) CheckResult
	}{
		{"controller", d.Controller},
		{"host", d.Host},
	}
	if runConnectivity {
		checks = append(checks, struct {
			kind string
			fn   func(context.Context) CheckResult
		}{"internet", d.Connectivity})
	}
	results := make(chan result, len(checks)+1)
	var group sync.WaitGroup
	for _, check := range checks {
		group.Add(1)
		go func(check struct {
			kind string
			fn   func(context.Context) CheckResult
		}) {
			defer group.Done()
			checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			results <- result{kind: check.kind, data: check.fn(checkCtx)}
		}(check)
	}
	if d.Modules != nil {
		group.Add(1)
		go func() {
			defer group.Done()
			checkCtx, cancel := context.WithTimeout(ctx, moduleCheckTimeout)
			defer cancel()
			results <- result{kind: "modules", modules: d.Modules(checkCtx)}
		}()
	}
	group.Wait()
	close(results)
	var connectivity CheckResult
	for result := range results {
		switch result.kind {
		case "controller":
			d.snapshot.Controller = d.controller.Update(result.data.Healthy, result.data.Detail)
			d.snapshot.ControllerUpdates = result.data.Update
			if d.snapshot.ControllerUpdates.State == "" {
				d.snapshot.ControllerUpdates = Component{State: Checking, Detail: "Controller update state unavailable"}
			}
			if d.configStaged {
				d.snapshot.ControllerUpdates = Component{State: Checking, Detail: "Boetticher configuration changes staged"}
			}
		case "host":
			if !result.data.Configured {
				d.snapshot.Host = Component{State: Off, Detail: result.data.Detail}
				d.snapshot.HostUpdates = Component{State: Off, Detail: "Host not enrolled"}
			} else {
				d.snapshot.Host = d.host.Update(result.data.Healthy, result.data.Detail)
				d.snapshot.HostUpdates = result.data.Update
				if d.snapshot.HostUpdates.State == "" {
					d.snapshot.HostUpdates = Component{State: Attention, Detail: "Host update state unavailable"}
				}
			}
		case "internet":
			connectivity = result.data
			d.lastConnectivity = result.data
			d.connectivityAt = now
		case "modules":
			d.applyModuleStatus(result.modules)
		}
	}
	if !runConnectivity {
		connectivity = d.lastConnectivity
	}
	if !connectivity.Configured && d.connectivityAt.IsZero() {
		connectivity.Configured = true
		connectivity.Detail = "waiting for first connectivity check"
	}
	if runConnectivity {
		connectivityComponent := d.internet.Update(connectivity.Healthy, connectivity.Detail)
		d.snapshot.Internet.Component = connectivityComponent
	}
	if !d.skipThroughput && connectivity.Healthy && (d.throughputTry.IsZero() || now.Sub(d.throughputTry) >= d.Settings.ThroughputInterval) {
		d.throughputTry = now
		throughputCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		value, err := d.Throughput(throughputCtx)
		cancel()
		if err != nil {
			d.Logger.Printf("throughput sample failed: %v", err)
		} else if value >= 0 {
			d.throughput, d.throughputAt = value, now
		}
	}
	d.snapshot.Internet.ThroughputMbps = d.throughput
	d.snapshot.Internet.ThroughputAt = d.throughputAt
	if d.snapshot.Internet.State != Failed && d.snapshot.Internet.State != Checking {
		if d.throughputAt.IsZero() || now.Sub(d.throughputAt) > 2*d.Settings.ThroughputInterval {
			d.snapshot.Internet.State = Attention
			d.snapshot.Internet.Detail = "Internet reachable; no recent usable throughput sample"
		} else if d.throughput >= d.Settings.HealthyMbps {
			d.snapshot.Internet.State = Healthy
			d.snapshot.Internet.Detail = fmt.Sprintf("Internet reachable; recent throughput %.0f Mbps", d.throughput)
		} else {
			d.snapshot.Internet.State = Attention
			d.snapshot.Internet.Detail = fmt.Sprintf("Internet reachable; recent throughput %.0f Mbps is below %.0f Mbps", d.throughput, d.Settings.HealthyMbps)
		}
	}
	d.scheduleTelemetry(ctx, now)
	d.streamdeckDirty = true
	d.logTransitions()
}

func (d *Daemon) applyModuleStatus(modules ModuleStatus) {
	d.snapshot.Firewall = debouncedModuleComponent(d.firewall, modules.Firewall)
	d.snapshot.VPN = moduleComponent(modules.VPN)
	d.snapshot.DHCPNTP = moduleComponent(modules.DHCPNTP)
	d.snapshot.DNS = moduleComponent(modules.DNS)
	d.snapshot.Tailnet = moduleComponent(modules.Tailnet)
	d.streamdeckDirty = true
	d.logTransitions()
}

func (d *Daemon) handleEvent(event OperationEvent) {
	if err := ValidateEvent(event); err != nil {
		d.Logger.Printf("ignored invalid operation event: %v", err)
		return
	}
	d.streamdeckDirty = true
	now := d.Now()
	switch event.Event {
	case "operation-start":
		if event.totalSteps() <= 0 {
			event.TotalSteps = PixelCount
		}
		d.operation = &operationDisplay{event: event}
		d.Logger.Printf("operation started: %s", event.Name)
	case "operation-progress":
		if d.operation != nil && d.operation.event.Name == event.Name {
			if event.Mode != "" {
				d.operation.event.Mode = event.Mode
			}
			d.operation.event.CurrentStep = event.CurrentStep
			d.operation.event.TotalSteps = event.totalSteps()
			d.operation.event.Detail = event.Detail
			if event.Tests != nil {
				d.operation.event.Tests = append([]TestResult(nil), event.Tests...)
			}
		}
	case "operation-success":
		if d.operation != nil && d.operation.event.Name == event.Name {
			d.operation.event = event
			d.operation.until = now.Add(terminalDisplayHold)
		}
		d.Logger.Printf("operation succeeded: %s", event.Name)
	case "operation-failure":
		if d.operation == nil || d.operation.event.Name != event.Name {
			d.operation = &operationDisplay{event: event}
		}
		d.operation.event = event
		d.operation.result = Failed
		d.operation.until = now.Add(terminalDisplayHold)
		d.Logger.Printf("operation failed: %s: %s", event.Name, event.Detail)
	case "configuration-staged":
		d.configStaged = true
		d.snapshot.ControllerUpdates = Component{State: Checking, Detail: "Boetticher configuration changes staged"}
	case "configuration-applied":
		d.configStaged = false
	}
}

func (d *Daemon) handleStreamDeckEvent(ctx context.Context, event KeyEvent) {
	if event.Index < 0 || event.Index >= StreamDeckKeyCount {
		return
	}
	now := d.Now()
	switch d.streamdeckView {
	case StreamDeckHome:
		switch {
		case event.Index == 0:
			d.streamdeckView = StreamDeckHostDetail
		case event.Index == 10:
			d.streamdeckView = StreamDeckNetworkDetail
		case event.Index == 11:
			d.streamdeckView = StreamDeckVPNDetail
		case event.Index == 12:
			d.streamdeckView = StreamDeckTailnetDetail
		case event.Index >= 5 && event.Index <= 9:
			index := d.streamdeckPage*5 + event.Index - 5
			if index < len(d.telemetry.Guests) {
				d.streamdeckGuest = index
				d.streamdeckView = StreamDeckGuestDetail
			}
		case event.Index == 13:
			pages := guestPageCount(len(d.telemetry.Guests))
			if pages > 1 {
				d.streamdeckPage = (d.streamdeckPage + 1) % pages
			}
		case event.Index == 14:
			d.requestTelemetry(ctx, now)
		}
	case StreamDeckHostDetail, StreamDeckGuestDetail, StreamDeckNetworkDetail, StreamDeckVPNDetail, StreamDeckTailnetDetail:
		switch event.Index {
		case 13:
			d.streamdeckView = StreamDeckHome
		case 14:
			d.requestTelemetry(ctx, now)
		}
	}
	d.streamdeckDirty = true
}

func (d *Daemon) requestTelemetry(ctx context.Context, now time.Time) {
	if !d.Settings.StreamDeckEnabled || d.Telemetry == nil {
		return
	}
	if !d.manualRefreshAt.IsZero() && now.Sub(d.manualRefreshAt) < 5*time.Second {
		return
	}
	d.manualRefreshAt = now
	d.telemetryAttempt = time.Time{}
	d.scheduleTelemetry(ctx, now)
}

func (d *Daemon) scheduleTelemetry(ctx context.Context, now time.Time) {
	if d.Telemetry == nil || d.telemetryRunning {
		return
	}
	if !d.telemetryAttempt.IsZero() && now.Sub(d.telemetryAttempt) < d.Settings.TelemetryInterval {
		return
	}
	d.telemetryAttempt = now
	d.telemetryRunning = true
	go func() {
		checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		snapshot, err := d.Telemetry(checkCtx)
		cancel()
		select {
		case d.telemetryResults <- telemetryResult{snapshot: snapshot, err: err}:
		case <-ctx.Done():
		}
	}()
}

func (d *Daemon) applyTelemetry(result telemetryResult) {
	d.telemetryRunning = false
	if result.err != nil {
		d.telemetry.Stale = true
		d.telemetry.Error = result.err.Error()
		if d.telemetry.FetchedAt.IsZero() {
			d.telemetry = ProxmoxSnapshot{Stale: true, Error: result.err.Error()}
		}
		d.Logger.Printf("Proxmox telemetry unavailable; retaining last good snapshot: %v", result.err)
	} else {
		result.snapshot.Stale = false
		result.snapshot.Error = ""
		d.telemetry = result.snapshot
	}
	d.streamdeckDirty = true
}

func (d *Daemon) render(ctx context.Context) {
	now := d.Now()
	if d.operation != nil && !d.operation.until.IsZero() && now.After(d.operation.until) {
		d.operation = nil
		d.streamdeckDirty = true
	}
	if d.Driver != nil && !d.driverBroken {
		var frame []Pixel
		if d.operation != nil {
			if d.operation.event.Mode == Standard {
				frame = d.renderer.Frame(d.snapshot, now)
			} else if d.operation.result == Failed {
				frame = d.renderer.FailureFrame(d.operation.event, now)
			} else {
				frame = d.renderer.OperationFrame(d.operation.event, now)
			}
		}
		if frame == nil {
			frame = d.renderer.Frame(d.snapshot, now)
		}
		showCtx, cancel := context.WithTimeout(ctx, time.Second)
		err := d.Driver.Show(showCtx, frame)
		cancel()
		if err != nil {
			d.driverBroken = true
			d.Logger.Printf("Blinkt unavailable; continuing without display: %v", err)
			_ = d.Driver.Close()
		}
	}
	if d.streamdeckNeedsMarquee() {
		if d.streamdeckAnimationAt.IsZero() || !now.Before(d.streamdeckAnimationAt) {
			d.streamdeckDirty = true
			d.streamdeckAnimationAt = now.Add(streamDeckMarqueeInterval)
		}
	} else {
		d.streamdeckAnimationAt = time.Time{}
	}
	d.queueStreamDeckRender(now)
}

func (d *Daemon) streamdeckNeedsMarquee() bool {
	if d.operation != nil {
		return false
	}
	switch d.streamdeckView {
	case StreamDeckHostDetail:
		return needsDeckMarquee(d.telemetry.Host.Node)
	case StreamDeckGuestDetail:
		if d.streamdeckGuest < 0 || d.streamdeckGuest >= len(d.telemetry.Guests) {
			return false
		}
		return needsDeckMarquee(d.telemetry.Guests[d.streamdeckGuest].Name)
	case StreamDeckNetworkDetail:
		return needsDeckMarquee(networkComponent(d.snapshot).Detail)
	case StreamDeckVPNDetail:
		return needsDeckMarquee(d.snapshot.VPN.Detail)
	case StreamDeckTailnetDetail:
		return needsDeckMarquee(d.snapshot.Tailnet.Detail)
	default:
		if needsDeckMarquee(d.telemetry.Host.Node) {
			return true
		}
		start := d.streamdeckPage * 5
		for index := start; index < len(d.telemetry.Guests) && index < start+5; index++ {
			if needsDeckMarquee(d.telemetry.Guests[index].Name) {
				return true
			}
		}
		return false
	}
}

func (d *Daemon) queueStreamDeckRender(now time.Time) {
	if !d.Settings.StreamDeckEnabled || d.streamdeckFrames == nil || !d.streamdeckDirty {
		return
	}
	frame := (StreamDeckRenderer{}).RenderAt(d.snapshot, d.telemetry, d.operation, d.streamdeckView, d.streamdeckPage, d.streamdeckGuest, now)
	select {
	case <-d.streamdeckFrames:
	default:
	}
	select {
	case d.streamdeckFrames <- frame:
		d.streamdeckDirty = false
	default:
	}
}

func (d *Daemon) startup(ctx context.Context) {
	if d.Driver == nil || d.driverBroken {
		return
	}
	for _, index := range []int{0, 1, 2, 3, 4, 5, 6, 7, 6, 4, 2, 0} {
		frame := make([]Pixel, PixelCount)
		frame[index] = d.renderer.componentPixel(Checking, d.Now(), index)
		d.show(ctx, frame)
		select {
		case <-ctx.Done():
			return
		case <-time.After(70 * time.Millisecond):
		}
	}
}

func (d *Daemon) show(ctx context.Context, frame []Pixel) {
	if d.Driver == nil || d.driverBroken {
		return
	}
	showCtx, cancel := context.WithTimeout(ctx, time.Second)
	if err := d.Driver.Show(showCtx, frame); err != nil {
		d.driverBroken = true
		d.Logger.Printf("Blinkt unavailable; continuing without display: %v", err)
	}
	cancel()
}

func (d *Daemon) shutdown(ctx context.Context) {
	d.Logger.Printf("status daemon stopping")
	if d.Driver == nil {
		return
	}
	clearCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	_ = d.Driver.Clear(clearCtx)
	cancel()
	_ = d.Driver.Close()
}

func (d *Daemon) logTransitions() {
	for _, transition := range []struct {
		name          string
		before, after State
		detail        string
	}{
		{"CTL", d.previous.Controller.State, d.snapshot.Controller.State, ""},
		{"HOST", d.previous.Host.State, d.snapshot.Host.State, ""},
		{"FW", d.previous.Firewall.State, d.snapshot.Firewall.State, ""},
		{"DHCP/NTP", d.previous.DHCPNTP.State, d.snapshot.DHCPNTP.State, ""},
		{"Tailnet", d.previous.Tailnet.State, d.snapshot.Tailnet.State, d.snapshot.Tailnet.Detail},
		{"NET", d.previous.Internet.State, d.snapshot.Internet.State, ""},
		{"CTRL-UPDATES", d.previous.ControllerUpdates.State, d.snapshot.ControllerUpdates.State, ""},
		{"HOST-UPDATES", d.previous.HostUpdates.State, d.snapshot.HostUpdates.State, ""},
	} {
		if transition.before != "" && transition.before != transition.after {
			if transition.name == "Tailnet" {
				d.Logger.Printf("%s state: %s -> %s (%s)", transition.name, transition.before, transition.after, tailnetTransitionDetail(transition.detail))
			} else {
				d.Logger.Printf("%s state: %s -> %s", transition.name, transition.before, transition.after)
			}
		}
	}
	d.previous = d.snapshot
}

func listen(ctx context.Context, path string) (net.Listener, func(), <-chan OperationEvent, error) {
	if path == "" {
		path = DefaultSocketPath
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, nil, nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, nil, nil, fmt.Errorf("status socket path is not a socket: %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, nil, nil, fmt.Errorf("remove stale status socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, nil, nil, err
	}
	events := make(chan OperationEvent, 16)
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				if ctx.Err() == nil {
					continue
				}
				return
			}
			go readEvent(connection, events)
		}
	}()
	cleanup := func() {
		_ = listener.Close()
		_ = os.Remove(path)
	}
	return listener, cleanup, events, nil
}

func readEvent(connection net.Conn, events chan<- OperationEvent) {
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	reader := bufio.NewReader(io.LimitReader(connection, 64<<10))
	line, err := reader.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return
	}
	var event OperationEvent
	if err := json.Unmarshal(line, &event); err != nil || ValidateEvent(event) != nil {
		return
	}
	select {
	case events <- event:
	default:
	}
}
