package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gofastercloud/boetticher/internal/labspeedtest"
	"github.com/showwin/speedtest-go/speedtest"
)

const (
	labChildBudget     = 120 * time.Second
	labProgressSpacing = time.Second
)

// runLabChild measures from inside the owned namespace. Name resolution uses
// the zone gateway, as ordinary LAB clients do; external DNS is denied by the
// firewall.
func runLabChild(gateway string, stdout io.Writer) int {
	writer := &eventWriter{out: stdout}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	net.DefaultResolver.PreferGo = true
	net.DefaultResolver.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, net.JoinHostPort(gateway, "53"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), labChildBudget)
	defer cancel()
	event := measureLab(ctx, writer.emit)
	writer.emit(event)
	if event.Phase != labspeedtest.PhaseDone {
		return 1
	}
	return 0
}

func measureLab(ctx context.Context, emit func(labspeedtest.Event)) labspeedtest.Event {
	client := speedtest.New(
		speedtest.WithDoer(&http.Client{Timeout: 20 * time.Second}),
		speedtest.WithUserConfig(&speedtest.UserConfig{
			PingMode:       speedtest.TCP,
			MaxConnections: 8,
			UserAgent:      "boetticher-host-speedtest/2",
		}),
	)
	servers, err := client.FetchServerListContext(ctx)
	if err != nil {
		return labspeedtest.ErrorEvent("fetch speedtest servers: %v", err)
	}
	targets, err := servers.FindServer(nil)
	if err != nil || len(targets) == 0 {
		return labspeedtest.ErrorEvent("select speedtest server: %v", err)
	}
	server := targets[0]
	result := labspeedtest.Event{Server: server.String()}
	emit(labspeedtest.Event{Phase: labspeedtest.PhaseServer, Server: result.Server})
	if err := server.PingTestContext(ctx, nil); err != nil {
		return labspeedtest.ErrorEvent("speedtest ping: %v", err)
	}
	result.LatencyMS, result.JitterMS = server.Latency.Seconds()*1000, server.Jitter.Seconds()*1000
	emit(labspeedtest.Event{Phase: labspeedtest.PhasePing, Server: result.Server, LatencyMS: result.LatencyMS, JitterMS: result.JitterMS})

	progress := newProgressThrottle(labProgressSpacing, emit)
	client.SetCallbackDownload(func(rate speedtest.ByteRate) {
		progress.offer(labspeedtest.Event{Phase: labspeedtest.PhaseDownload, DownloadMbps: rate.Mbps()})
	})
	client.SetCallbackUpload(func(rate speedtest.ByteRate) {
		progress.offer(labspeedtest.Event{Phase: labspeedtest.PhaseUpload, UploadMbps: rate.Mbps()})
	})
	if err := server.DownloadTestContext(ctx); err != nil {
		return labspeedtest.ErrorEvent("speedtest download: %v", err)
	}
	result.DownloadMbps = server.DLSpeed.Mbps()
	progress.flush(labspeedtest.Event{Phase: labspeedtest.PhaseDownload, DownloadMbps: result.DownloadMbps})
	if err := server.UploadTestContext(ctx); err != nil {
		return labspeedtest.ErrorEvent("speedtest upload: %v", err)
	}
	result.UploadMbps = server.ULSpeed.Mbps()
	progress.flush(labspeedtest.Event{Phase: labspeedtest.PhaseUpload, UploadMbps: result.UploadMbps})
	result.Phase = labspeedtest.PhaseDone
	if err := labspeedtest.Validate(result); err != nil {
		return labspeedtest.ErrorEvent("speedtest result: %v", err)
	}
	return result
}

// progressThrottle forwards at most one live-rate event per spacing so the
// SSH stream and StreamDeck redraws stay bounded.
type progressThrottle struct {
	mu      sync.Mutex
	spacing time.Duration
	last    time.Time
	now     func() time.Time
	emit    func(labspeedtest.Event)
}

func newProgressThrottle(spacing time.Duration, emit func(labspeedtest.Event)) *progressThrottle {
	return &progressThrottle{spacing: spacing, now: time.Now, emit: emit}
}

func (p *progressThrottle) offer(event labspeedtest.Event) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if !p.last.IsZero() && now.Sub(p.last) < p.spacing {
		return
	}
	p.last = now
	p.emit(event)
}

func (p *progressThrottle) flush(event labspeedtest.Event) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.last = p.now()
	p.emit(event)
}
