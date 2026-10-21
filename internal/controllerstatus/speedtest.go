package controllerstatus

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/labspeedtest"
)

// labSpeedtestTimeout bounds one manual run end to end. The Host helper has
// its own 150 s measurement budget plus a fresh 30 s cleanup budget, so it
// reports its own terminal event before this Controller-side bound expires.
const labSpeedtestTimeout = 3*time.Minute + 15*time.Second

// speedtestNoticeHold is how long a refused press shows its reason.
const speedtestNoticeHold = 3 * time.Second

// LabSpeedtestRunner streams the Host helper's lab mode over the strict
// Controller-to-Host SSH transport.
type LabSpeedtestRunner struct {
	LoadConfig func() (controllerhost.LabConfig, error)
	Transport  func(controllerhost.LabConfig) (controllerhost.Transport, error)
	Stream     func(context.Context, controllerhost.Transport, string, func([]byte)) (controllerhost.Result, error)
}

// Run invokes the helper and forwards every validated progress event. It
// returns the terminal event; a missing or malformed stream is an error,
// never a result.
func (r LabSpeedtestRunner) Run(ctx context.Context, emit func(labspeedtest.Event)) (labspeedtest.Event, error) {
	load := r.LoadConfig
	if load == nil {
		load = controllerhost.LoadConfig
	}
	config, err := load()
	if errors.Is(err, os.ErrNotExist) || (err == nil && config.Proxmox.Node == "") {
		return labspeedtest.Event{}, errors.New("Host not enrolled")
	}
	if err != nil {
		return labspeedtest.Event{}, fmt.Errorf("read Host configuration: %w", err)
	}
	transportFor := r.Transport
	if transportFor == nil {
		transportFor = controllerhost.TransportFor
	}
	transport, err := transportFor(config)
	if err != nil {
		return labspeedtest.Event{}, err
	}
	transport.Timeout = labSpeedtestTimeout
	stream := r.Stream
	if stream == nil {
		stream = func(ctx context.Context, transport controllerhost.Transport, command string, onLine func([]byte)) (controllerhost.Result, error) {
			return transport.RunLines(ctx, command, labspeedtest.MaxEventBytes, onLine)
		}
	}
	var terminal *labspeedtest.Event
	var protocolErr error
	_, runErr := stream(ctx, transport, labspeedtest.LabCommand, func(line []byte) {
		if protocolErr != nil || terminal != nil {
			return
		}
		event, err := labspeedtest.ParseEvent(line)
		if err != nil {
			protocolErr = err
			return
		}
		if event.Terminal() {
			terminal = &event
			return
		}
		emit(event)
	})
	switch {
	case protocolErr != nil:
		return labspeedtest.Event{}, fmt.Errorf("lab speedtest progress: %w", protocolErr)
	case terminal != nil:
		// The helper exits non-zero after an error event; the event itself is
		// the meaningful detail, not the SSH exit status.
		return *terminal, nil
	case runErr != nil:
		return labspeedtest.Event{}, fmt.Errorf("lab speedtest failed: %w", runErr)
	default:
		return labspeedtest.Event{}, errors.New("lab speedtest returned no result")
	}
}

type speedtestUpdate struct {
	event labspeedtest.Event
	final bool
	err   error
	at    time.Time
}

// SpeedtestDisplay is the daemon-owned state of the manual lab speedtest. It
// is independent of the view so a run survives navigation, and it never feeds
// the hourly NET/Blinkt throughput figure.
type SpeedtestDisplay struct {
	Running     bool
	Phase       labspeedtest.Phase
	Server      string
	LatencyMS   float64
	JitterMS    float64
	Download    float64
	Upload      float64
	Error       string
	Recovered   bool
	StartedAt   time.Time
	FinishedAt  time.Time
	Notice      string
	NoticeUntil time.Time
}

func (s *SpeedtestDisplay) start(now time.Time) {
	*s = SpeedtestDisplay{Running: true, Phase: labspeedtest.PhaseSetup, StartedAt: now}
}

func (s *SpeedtestDisplay) notice(text string, now time.Time) {
	s.Notice, s.NoticeUntil = text, now.Add(speedtestNoticeHold)
}

func (s *SpeedtestDisplay) apply(update speedtestUpdate) {
	event := update.event
	if update.err != nil {
		event = labspeedtest.Event{Phase: labspeedtest.PhaseError, Error: update.err.Error()}
	}
	if event.Phase != "" {
		s.Phase = event.Phase
	}
	if event.Server != "" {
		s.Server = event.Server
	}
	if event.Recovered {
		s.Recovered = true
	}
	switch event.Phase {
	case labspeedtest.PhasePing:
		s.LatencyMS, s.JitterMS = event.LatencyMS, event.JitterMS
	case labspeedtest.PhaseDownload:
		s.Download = event.DownloadMbps
	case labspeedtest.PhaseUpload:
		s.Upload = event.UploadMbps
	case labspeedtest.PhaseDone, labspeedtest.PhaseError:
		// A failed run keeps any figures measured before the failure.
		keep := func(target *float64, value float64) {
			if value > 0 || event.Phase == labspeedtest.PhaseDone {
				*target = value
			}
		}
		keep(&s.LatencyMS, event.LatencyMS)
		keep(&s.JitterMS, event.JitterMS)
		keep(&s.Download, event.DownloadMbps)
		keep(&s.Upload, event.UploadMbps)
		s.Error = event.Error
	}
	if update.final {
		s.Running = false
		s.FinishedAt = update.at
		if s.Phase != labspeedtest.PhaseDone && s.Phase != labspeedtest.PhaseError {
			s.Phase, s.Error = labspeedtest.PhaseError, "lab speedtest ended without a result"
		}
	}
}

func phaseLabel(phase labspeedtest.Phase) string {
	switch phase {
	case labspeedtest.PhaseSetup:
		return "SETUP"
	case labspeedtest.PhaseServer:
		return "SERVER"
	case labspeedtest.PhasePing:
		return "PING"
	case labspeedtest.PhaseDownload:
		return "DOWN"
	case labspeedtest.PhaseUpload:
		return "UP"
	case labspeedtest.PhaseDone:
		return "DONE"
	case labspeedtest.PhaseError:
		return "FAILED"
	default:
		return "START"
	}
}

func formatMbps(value float64) string {
	if value <= 0 {
		return "—"
	}
	if value >= 100 {
		return fmt.Sprintf("%.0f Mbps", value)
	}
	return fmt.Sprintf("%.1f Mbps", value)
}

// ST-VPN is deliberately not runnable: VPN egress is selected only for
// declared VPN client reservations, so an honest test needs durable intent.
const stVPNUnavailable = "ST-VPN needs a declared VPN probe client; not available"

// renderSpeedtestKeys fills NETWORK keys 5-10: ST-LAB, ST-VPN, and the split
// PING/DOWN/UP/SERVER figures of the current or last lab run.
func renderSpeedtestKeys(keys []KeyImage, s SpeedtestDisplay, now time.Time) {
	value, footer, state := "START", "PRESS", Off
	switch {
	case s.Running:
		value, footer, state = phaseLabel(s.Phase), "RUNNING", Checking
		switch s.Phase {
		case labspeedtest.PhaseDownload:
			value = "↓" + shortMbps(s.Download)
		case labspeedtest.PhaseUpload:
			value = "↑" + shortMbps(s.Upload)
		}
	case s.Phase == labspeedtest.PhaseDone:
		value, footer, state = shortMbps(s.Download)+"/"+shortMbps(s.Upload), s.FinishedAt.Local().Format("15:04"), Healthy
	case s.Phase == labspeedtest.PhaseError:
		value, footer, state = "FAILED", s.FinishedAt.Local().Format("15:04"), Failed
	}
	if s.Notice != "" && now.Before(s.NoticeUntil) {
		footer = s.Notice
	}
	keys[5] = renderDeckKey("ST-LAB", value, footer, state)
	keys[6] = renderDeckKey("ST-VPN", "N/A", "NO PROBE", Off)
	if s.StartedAt.IsZero() {
		return
	}
	figureState := state
	keys[7] = renderDeckKey("PING", formatLatency(s.LatencyMS), "LAB", figureState)
	keys[8] = renderDeckKey("DOWN", formatMbps(s.Download), "LAB", figureState)
	keys[9] = renderDeckKey("UP", formatMbps(s.Upload), "LAB", figureState)
	detail := speedtestDetail(s)
	if detail == "" {
		detail = "—"
	}
	keys[10] = renderDeckKeyAt("SERVER", detail, "LAB", figureState, now, true)
}

func speedtestDetail(s SpeedtestDisplay) string {
	if s.StartedAt.IsZero() {
		return ""
	}
	detail := s.Server
	if s.Phase == labspeedtest.PhaseError && s.Error != "" {
		detail = s.Error
	}
	if s.Recovered && !s.Running {
		detail += " (recovered leftover fixture)"
	}
	return detail
}

func shortMbps(value float64) string {
	if value <= 0 {
		return "—"
	}
	if value >= 10 {
		return fmt.Sprintf("%.0fM", value)
	}
	return fmt.Sprintf("%.1fM", value)
}

func formatLatency(value float64) string {
	if value <= 0 {
		return "—"
	}
	return fmt.Sprintf("%.0f ms", value)
}
