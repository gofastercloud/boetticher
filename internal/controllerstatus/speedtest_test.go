package controllerstatus

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/labspeedtest"
)

func speedtestDaemon(t *testing.T) *Daemon {
	t.Helper()
	d := NewDaemon(DefaultSettings(), nil)
	d.snapshot.Firewall = Component{State: Healthy, Detail: "firewall healthy"}
	d.streamdeckView = StreamDeckNetworkDetail
	return d
}

func receiveUpdate(t *testing.T, d *Daemon) speedtestUpdate {
	t.Helper()
	select {
	case update := <-d.speedtestUpdates:
		return update
	case <-time.After(2 * time.Second):
		t.Fatal("no speedtest update arrived")
		return speedtestUpdate{}
	}
}

func TestLabSpeedtestRunnerStreamsProgressAndReturnsTerminal(t *testing.T) {
	var command string
	runner := LabSpeedtestRunner{
		LoadConfig: func() (controllerhost.LabConfig, error) {
			return controllerhost.LabConfig{Proxmox: controllerhost.ProxmoxConfig{Node: "pve", Address: "192.0.2.10"}}, nil
		},
		Transport: func(controllerhost.LabConfig) (controllerhost.Transport, error) {
			return controllerhost.Transport{}, nil
		},
		Stream: func(_ context.Context, transport controllerhost.Transport, value string, onLine func([]byte)) (controllerhost.Result, error) {
			command = value
			if transport.Timeout != labSpeedtestTimeout {
				t.Errorf("transport timeout = %s", transport.Timeout)
			}
			for _, line := range []string{`{"phase":"setup"}`, `{"phase":"ping","latency_ms":9}`, `{"phase":"download","download_mbps":300}`, `{"phase":"done","download_mbps":600,"upload_mbps":40}`} {
				onLine([]byte(line))
			}
			return controllerhost.Result{}, nil
		},
	}
	var progress []labspeedtest.Phase
	terminal, err := runner.Run(context.Background(), func(event labspeedtest.Event) { progress = append(progress, event.Phase) })
	if err != nil || terminal.Phase != labspeedtest.PhaseDone || terminal.DownloadMbps != 600 {
		t.Fatalf("terminal=%#v err=%v", terminal, err)
	}
	if command != "/usr/local/libexec/boetticher-host-speedtest --lab --stream" {
		t.Fatalf("command = %q", command)
	}
	if len(progress) != 3 || progress[2] != labspeedtest.PhaseDownload {
		t.Fatalf("progress = %#v", progress)
	}
}

func TestLabSpeedtestRunnerTreatsBadStreamsAsErrors(t *testing.T) {
	enrolled := func() (controllerhost.LabConfig, error) {
		return controllerhost.LabConfig{Proxmox: controllerhost.ProxmoxConfig{Node: "pve"}}, nil
	}
	transport := func(controllerhost.LabConfig) (controllerhost.Transport, error) {
		return controllerhost.Transport{}, nil
	}
	cases := map[string]struct {
		lines []string
		err   error
		want  string
	}{
		"malformed line":       {lines: []string{`{"phase":"setup"}`, `garbage`}, want: "progress"},
		"no terminal":          {lines: []string{`{"phase":"setup"}`}, want: "no result"},
		"transport failure":    {err: errors.New("ssh exploded"), want: "ssh exploded"},
		"helper error is kept": {lines: []string{`{"phase":"error","error":"a firewall test or lab speedtest is already running on the Host"}`}, err: errors.New("exit status 1")},
	}
	for name, item := range cases {
		t.Run(name, func(t *testing.T) {
			runner := LabSpeedtestRunner{LoadConfig: enrolled, Transport: transport, Stream: func(_ context.Context, _ controllerhost.Transport, _ string, onLine func([]byte)) (controllerhost.Result, error) {
				for _, line := range item.lines {
					onLine([]byte(line))
				}
				return controllerhost.Result{}, item.err
			}}
			terminal, err := runner.Run(context.Background(), func(labspeedtest.Event) {})
			if item.want == "" {
				if err != nil || terminal.Phase != labspeedtest.PhaseError || !strings.Contains(terminal.Error, "already running") {
					t.Fatalf("helper error event lost: %#v %v", terminal, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("err = %v, want %q", err, item.want)
			}
		})
	}
	if _, err := (LabSpeedtestRunner{LoadConfig: func() (controllerhost.LabConfig, error) { return controllerhost.LabConfig{}, nil }}).Run(context.Background(), func(labspeedtest.Event) {}); err == nil || !strings.Contains(err.Error(), "not enrolled") {
		t.Fatalf("unenrolled Host ran a speedtest: %v", err)
	}
}

func TestLabSpeedtestPressIsSingleFlightAndSurvivesNavigation(t *testing.T) {
	d := speedtestDaemon(t)
	release := make(chan struct{})
	starts := 0
	d.LabSpeedtest = func(ctx context.Context, emit func(labspeedtest.Event)) (labspeedtest.Event, error) {
		starts++
		emit(labspeedtest.Event{Phase: labspeedtest.PhaseDownload, DownloadMbps: 321})
		<-release
		return labspeedtest.Event{Phase: labspeedtest.PhaseDone, Server: "Example", LatencyMS: 8, DownloadMbps: 612, UploadMbps: 41}, nil
	}
	ctx := context.Background()
	d.handleStreamDeckEvent(ctx, KeyEvent{Index: 5})
	if !d.labSpeedtest.Running {
		t.Fatal("press did not start a lab speedtest")
	}
	d.applySpeedtestUpdate(receiveUpdate(t, d))
	if d.labSpeedtest.Download != 321 || d.labSpeedtest.Phase != labspeedtest.PhaseDownload {
		t.Fatalf("live progress = %#v", d.labSpeedtest)
	}
	d.handleStreamDeckEvent(ctx, KeyEvent{Index: 5})
	if d.labSpeedtest.Notice != "BUSY" {
		t.Fatalf("second press notice = %q", d.labSpeedtest.Notice)
	}
	keys := (StreamDeckRenderer{Speedtest: d.labSpeedtest}).RenderAt(d.snapshot, d.telemetry, nil, StreamDeckNetworkDetail, 0, -1, d.Now())
	if keys[5].Footer != "BUSY" || keys[5].State != Checking {
		t.Fatalf("busy key = %#v", keys[5])
	}
	d.handleStreamDeckEvent(ctx, KeyEvent{Index: 13})
	if d.streamdeckView != StreamDeckHome || !d.labSpeedtest.Running {
		t.Fatal("leaving the view stopped the speedtest")
	}
	d.scheduleThroughput(ctx, d.Now())
	if d.throughputRunning {
		t.Fatal("hourly sample started while a lab speedtest was running")
	}
	close(release)
	d.applySpeedtestUpdate(receiveUpdate(t, d))
	if d.labSpeedtest.Running || d.labSpeedtest.Phase != labspeedtest.PhaseDone || d.labSpeedtest.Download != 612 || d.labSpeedtest.FinishedAt.IsZero() {
		t.Fatalf("final result = %#v", d.labSpeedtest)
	}
	if d.throughput != 0 || !d.throughputAt.IsZero() || d.snapshot.Internet.ThroughputMbps != 0 {
		t.Fatal("manual result fed the hourly NET throughput figure")
	}
	d.handleStreamDeckEvent(ctx, KeyEvent{Index: 10})
	keys = (StreamDeckRenderer{Speedtest: d.labSpeedtest}).RenderAt(d.snapshot, d.telemetry, nil, d.streamdeckView, 0, -1, d.Now())
	if keys[5].State != Healthy || keys[5].Value != "612M/41M" || keys[8].Value != "612 Mbps" {
		t.Fatalf("result after returning = %#v / %#v", keys[5], keys[8])
	}
	if starts != 1 {
		t.Fatalf("speedtest started %d times", starts)
	}
}

func TestLabSpeedtestPressRefusesWhenItWouldCollide(t *testing.T) {
	d := speedtestDaemon(t)
	d.LabSpeedtest = func(context.Context, func(labspeedtest.Event)) (labspeedtest.Event, error) {
		t.Fatal("speedtest started despite a refusal")
		return labspeedtest.Event{}, nil
	}
	d.throughputRunning = true
	d.handleStreamDeckEvent(context.Background(), KeyEvent{Index: 5})
	if d.labSpeedtest.Running || d.labSpeedtest.Notice != "HOURLY" {
		t.Fatalf("hourly collision = %#v", d.labSpeedtest)
	}
	d.throughputRunning = false
	d.snapshot.Firewall = Component{State: Off}
	d.handleStreamDeckEvent(context.Background(), KeyEvent{Index: 5})
	if d.labSpeedtest.Running || d.labSpeedtest.Notice != "NO FW" {
		t.Fatalf("no-firewall press = %#v", d.labSpeedtest)
	}
	d.snapshot.Firewall = Component{State: Healthy}
	d.handleStreamDeckEvent(context.Background(), KeyEvent{Index: 6})
	if d.labSpeedtest.Running {
		t.Fatal("ST-VPN started a run")
	}
	d.streamdeckView = StreamDeckHostDetail
	d.handleStreamDeckEvent(context.Background(), KeyEvent{Index: 5})
	if d.labSpeedtest.Running {
		t.Fatal("key 5 outside NETWORK started a run")
	}
}

func TestLabSpeedtestFailureKeepsPartialFigures(t *testing.T) {
	d := speedtestDaemon(t)
	d.LabSpeedtest = func(_ context.Context, emit func(labspeedtest.Event)) (labspeedtest.Event, error) {
		emit(labspeedtest.Event{Phase: labspeedtest.PhasePing, LatencyMS: 12})
		return labspeedtest.Event{}, errors.New("lab speedtest failed: Proxmox SSH command timed out")
	}
	d.handleStreamDeckEvent(context.Background(), KeyEvent{Index: 5})
	d.applySpeedtestUpdate(receiveUpdate(t, d))
	d.applySpeedtestUpdate(receiveUpdate(t, d))
	if d.labSpeedtest.Running || d.labSpeedtest.Phase != labspeedtest.PhaseError || d.labSpeedtest.LatencyMS != 12 || !strings.Contains(d.labSpeedtest.Error, "timed out") {
		t.Fatalf("failure state = %#v", d.labSpeedtest)
	}
	if !d.streamdeckNeedsMarquee() {
		t.Fatal("long failure detail is not animated")
	}
}

func TestNetworkSpeedtestKeysRenderEachState(t *testing.T) {
	now := time.Date(2026, 10, 21, 14, 5, 0, 0, time.Local)
	started := now.Add(-time.Minute)
	cases := []struct {
		name    string
		display SpeedtestDisplay
		value   string
		footer  string
		state   State
		figures bool
	}{
		{"idle", SpeedtestDisplay{}, "START", "PRESS", Off, false},
		{"setup", SpeedtestDisplay{Running: true, Phase: labspeedtest.PhaseSetup, StartedAt: started}, "SETUP", "RUNNING", Checking, true},
		{"ping", SpeedtestDisplay{Running: true, Phase: labspeedtest.PhasePing, LatencyMS: 9, StartedAt: started}, "PING", "RUNNING", Checking, true},
		{"download", SpeedtestDisplay{Running: true, Phase: labspeedtest.PhaseDownload, Download: 412.4, StartedAt: started}, "↓412M", "RUNNING", Checking, true},
		{"upload", SpeedtestDisplay{Running: true, Phase: labspeedtest.PhaseUpload, Download: 600, Upload: 7.25, StartedAt: started}, "↑7.2M", "RUNNING", Checking, true},
		{"done", SpeedtestDisplay{Phase: labspeedtest.PhaseDone, Download: 600, Upload: 40, LatencyMS: 9, Server: "Example", StartedAt: started, FinishedAt: now}, "600M/40M", "14:05", Healthy, true},
		{"failed", SpeedtestDisplay{Phase: labspeedtest.PhaseError, Error: "speedtest ping: timeout", StartedAt: started, FinishedAt: now}, "FAILED", "14:05", Failed, true},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			keys := (StreamDeckRenderer{Speedtest: item.display}).RenderAt(NewSnapshot(true), ProxmoxSnapshot{}, nil, StreamDeckNetworkDetail, 0, -1, now)
			if keys[5].Title != "ST-LAB" || keys[5].Value != item.value || keys[5].Footer != item.footer || keys[5].State != item.state {
				t.Fatalf("ST-LAB = %q/%q/%q/%s", keys[5].Title, keys[5].Value, keys[5].Footer, keys[5].State)
			}
			if keys[6].Title != "ST-VPN" || keys[6].Value != "N/A" || keys[6].State != Off {
				t.Fatalf("ST-VPN = %#v", keys[6])
			}
			if item.figures != (keys[7].Title == "PING" && keys[8].Title == "DOWN" && keys[9].Title == "UP" && keys[10].Title == "SERVER") {
				t.Fatalf("split figures shown=%t: %q %q %q %q", item.figures, keys[7].Title, keys[8].Title, keys[9].Title, keys[10].Title)
			}
			if keys[13].Title != "BACK" || keys[14].Title != "REFRESH" || keys[11].Title != "" || keys[12].Title != "" {
				t.Fatal("NETWORK navigation keys moved")
			}
		})
	}
	failed := (StreamDeckRenderer{Speedtest: cases[6].display}).RenderAt(NewSnapshot(true), ProxmoxSnapshot{}, nil, StreamDeckNetworkDetail, 0, -1, now)
	if failed[10].Value != "speedtest ping: timeout" || failed[10].State != Failed {
		t.Fatalf("failure detail = %#v", failed[10])
	}
	home := (StreamDeckRenderer{Speedtest: cases[5].display}).RenderAt(NewSnapshot(true), ProxmoxSnapshot{}, nil, StreamDeckHome, 0, -1, now)
	if home[4].Title != "NET" || home[4].Value == "600M" {
		t.Fatalf("manual result leaked into home NET key: %#v", home[4])
	}
}
