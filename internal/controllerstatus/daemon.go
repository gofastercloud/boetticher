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
	Settings     Settings
	Driver       Driver
	Logger       *log.Logger
	Controller   func(context.Context) CheckResult
	Host         func(context.Context) CheckResult
	Connectivity func(context.Context) CheckResult
	Throughput   func(context.Context) (float64, error)
	Now          func() time.Time

	renderer         Renderer
	snapshot         StatusSnapshot
	controller       *Debouncer
	host             *Debouncer
	internet         *Debouncer
	throughput       float64
	throughputAt     time.Time
	throughputTry    time.Time
	connectivityAt   time.Time
	lastConnectivity CheckResult
	operation        *operationDisplay
	configStaged     bool
	previous         StatusSnapshot
	driverBroken     bool
}

type operationDisplay struct {
	event  OperationEvent
	result State
	until  time.Time
}

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
	if settings.HealthyMbps <= 0 {
		settings.HealthyMbps = DefaultHealthyMbps
	}
	if settings.SocketPath == "" {
		settings.SocketPath = DefaultSocketPath
	}
	return &Daemon{
		Settings:   settings,
		Driver:     driver,
		Logger:     log.New(io.Discard, "", 0),
		Now:        time.Now,
		renderer:   NewRenderer(settings.Brightness),
		controller: NewDebouncer(Checking),
		host:       NewDebouncer(Checking),
		internet:   NewDebouncer(Checking),
		snapshot:   NewSnapshot(false),
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
	if d.Connectivity == nil {
		d.Connectivity = (HostConnectivityChecker{}).Check
	}
	if d.Throughput == nil {
		d.Throughput = func(ctx context.Context) (float64, error) {
			return (HostSpeedtestChecker{}).Sample(ctx)
		}
	}
	_, cleanup, events, err := listen(ctx, d.Settings.SocketPath)
	if err != nil {
		return err
	}
	defer cleanup()
	d.Logger.Printf("status daemon started; polling every %s", d.Settings.Interval)
	d.startup(ctx)
	d.refresh(ctx)
	d.render(ctx)
	ticker := time.NewTicker(d.Settings.Interval)
	defer ticker.Stop()
	frameTicker := time.NewTicker(100 * time.Millisecond)
	defer frameTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			d.shutdown(ctx)
			return nil
		case event := <-events:
			d.handleEvent(event)
			d.render(ctx)
		case now := <-ticker.C:
			d.refreshAt(ctx, now)
			d.render(ctx)
		case <-frameTicker.C:
			d.render(ctx)
		}
	}
}

func (d *Daemon) refresh(ctx context.Context) {
	d.refreshAt(ctx, d.Now())
}

func (d *Daemon) refreshAt(ctx context.Context, now time.Time) {
	type result struct {
		kind string
		data CheckResult
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
	results := make(chan result, len(checks))
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
	if connectivity.Healthy && (d.throughputTry.IsZero() || now.Sub(d.throughputTry) >= d.Settings.ThroughputInterval) {
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
	d.logTransitions()
}

func (d *Daemon) handleEvent(event OperationEvent) {
	if err := ValidateEvent(event); err != nil {
		d.Logger.Printf("ignored invalid operation event: %v", err)
		return
	}
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
			d.operation.event.CurrentStep = event.CurrentStep
			d.operation.event.TotalSteps = event.totalSteps()
			d.operation.event.Detail = event.Detail
		}
	case "operation-success":
		if d.operation == nil || d.operation.event.Name != event.Name {
			if event.TotalSteps <= 0 && event.Steps <= 0 {
				event.TotalSteps = PixelCount
			}
			d.operation = &operationDisplay{event: event}
		}
		d.operation.event.CurrentStep = d.operation.event.totalSteps()
		d.operation.result = Healthy
		d.operation.until = now.Add(time.Second)
		d.Logger.Printf("operation succeeded: %s", event.Name)
	case "operation-failure":
		if d.operation == nil || d.operation.event.Name != event.Name {
			d.operation = &operationDisplay{event: event}
		}
		d.operation.result = Failed
		d.operation.until = now.Add(time.Second)
		d.Logger.Printf("operation failed: %s: %s", event.Name, event.Detail)
	case "configuration-staged":
		d.configStaged = true
		d.snapshot.ControllerUpdates = Component{State: Checking, Detail: "Boetticher configuration changes staged"}
	case "configuration-applied":
		d.configStaged = false
	}
}

func (d *Daemon) render(ctx context.Context) {
	if d.Driver == nil || d.driverBroken {
		return
	}
	now := d.Now()
	var frame []Pixel
	if d.operation != nil {
		if !d.operation.until.IsZero() && now.After(d.operation.until) {
			d.operation = nil
		} else if d.operation.result == Failed {
			frame = d.renderer.FailureFrame(d.operation.event, now)
		} else if d.operation.result == Healthy {
			frame = d.renderer.OperationFrame(d.operation.event, now)
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
	}{
		{"CTL", d.previous.Controller.State, d.snapshot.Controller.State},
		{"HOST", d.previous.Host.State, d.snapshot.Host.State},
		{"NET", d.previous.Internet.State, d.snapshot.Internet.State},
		{"CTRL-UPDATES", d.previous.ControllerUpdates.State, d.snapshot.ControllerUpdates.State},
		{"HOST-UPDATES", d.previous.HostUpdates.State, d.snapshot.HostUpdates.State},
	} {
		if transition.before != "" && transition.before != transition.after {
			d.Logger.Printf("%s state: %s -> %s", transition.name, transition.before, transition.after)
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
