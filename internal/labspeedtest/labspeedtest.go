// Package labspeedtest is the fixed contract between the Controller status
// daemon and the Host speedtest helper's lab mode.
//
// Lab mode measures ordinary LAB egress from a temporary, owned network
// namespace attached to the SERVERS VLAN behind the firewall. The helper
// streams one JSON event per line so peripherals can show live progress.
package labspeedtest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
)

const (
	// HelperVersion is reported by `--version` and checked by Host preparation
	// so a stale helper is reinstalled by the normal `host apply` path.
	HelperVersion = "boetticher-host-speedtest/v2"
	HelperPath    = "/usr/local/libexec/boetticher-host-speedtest"
	// LabCommand is the only lab-mode measurement the Controller issues.
	LabCommand = HelperPath + " --lab --stream"
	// CleanupCommand removes an owned fixture left by an interrupted run. It
	// is Host-local and needs no provider. A Host still on helper v1 (which
	// has no lab mode, so cannot own a fixture) reports that instead of
	// failing on an unknown flag.
	CleanupCommand = "set -eu; if [ \"$(" + HelperPath + " --version 2>/dev/null || true)\" != " + "'" + HelperVersion + "'" + " ]; then printf '%s\\n' '{\"phase\":\"cleanup\",\"helper_absent\":true}'; exit 0; fi; exec " + HelperPath + " --lab --cleanup-only"

	// The fixture uses the fixed SERVERS network contract and the reserved
	// .250-.254 probe space, outside the VPN-protected .224/28 range, so its
	// traffic takes the ordinary firewall WAN egress.
	Zone      = "SERVERS"
	VLAN      = 20
	Subnet    = "10.10.20.0/24"
	Gateway   = "10.10.20.1"
	Namespace = "bt4s-lab"
	HostVeth  = "bt4s-lab-h"

	// MaxEventBytes bounds a single progress line on both sides.
	MaxEventBytes = 1024
	maxErrorRunes = 240
)

type Phase string

const (
	PhaseSetup    Phase = "setup"
	PhaseServer   Phase = "server"
	PhasePing     Phase = "ping"
	PhaseDownload Phase = "download"
	PhaseUpload   Phase = "upload"
	PhaseDone     Phase = "done"
	PhaseError    Phase = "error"
	// PhaseCleanup is the terminal event of a cleanup-only run.
	PhaseCleanup Phase = "cleanup"
)

// Event is one progress line. Rates are megabits per second; download and
// upload events carry the live rate and the final done event carries all
// measured figures.
type Event struct {
	Phase        Phase   `json:"phase"`
	Server       string  `json:"server,omitempty"`
	LatencyMS    float64 `json:"latency_ms,omitempty"`
	JitterMS     float64 `json:"jitter_ms,omitempty"`
	DownloadMbps float64 `json:"download_mbps,omitempty"`
	UploadMbps   float64 `json:"upload_mbps,omitempty"`
	Recovered    bool    `json:"recovered_leftovers,omitempty"`
	HelperAbsent bool    `json:"helper_absent,omitempty"`
	Error        string  `json:"error,omitempty"`
}

func (e Event) Terminal() bool {
	return e.Phase == PhaseDone || e.Phase == PhaseError || e.Phase == PhaseCleanup
}

// ErrorEvent builds a bounded error event.
func ErrorEvent(format string, args ...any) Event {
	return Event{Phase: PhaseError, Error: clampError(fmt.Sprintf(format, args...))}
}

// Encode returns the newline-terminated wire form of an event.
func Encode(event Event) ([]byte, error) {
	if err := Validate(event); err != nil {
		return nil, err
	}
	data, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	if len(data)+1 > MaxEventBytes {
		return nil, errors.New("speedtest progress event is too large")
	}
	return append(data, '\n'), nil
}

// ParseEvent strictly decodes one progress line. Unknown fields, phases, or
// implausible values are protocol failures rather than displayable results.
func ParseEvent(line []byte) (Event, error) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return Event{}, errors.New("empty speedtest progress line")
	}
	if len(line) > MaxEventBytes {
		return Event{}, errors.New("speedtest progress line is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	var event Event
	if err := decoder.Decode(&event); err != nil {
		return Event{}, fmt.Errorf("decode speedtest progress: %w", err)
	}
	if decoder.More() {
		return Event{}, errors.New("speedtest progress line has trailing data")
	}
	if err := Validate(event); err != nil {
		return Event{}, err
	}
	return event, nil
}

func Validate(event Event) error {
	switch event.Phase {
	case PhaseSetup, PhaseServer, PhasePing, PhaseDownload, PhaseUpload, PhaseDone, PhaseCleanup:
		if event.Error != "" {
			return fmt.Errorf("speedtest %s event carries an error", event.Phase)
		}
	case PhaseError:
		if strings.TrimSpace(event.Error) == "" {
			return errors.New("speedtest error event has no detail")
		}
	default:
		return fmt.Errorf("unknown speedtest phase %q", event.Phase)
	}
	for _, value := range []float64{event.LatencyMS, event.JitterMS, event.DownloadMbps, event.UploadMbps} {
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 1_000_000 {
			return errors.New("speedtest progress value is out of range")
		}
	}
	if len(event.Server) > 200 || strings.ContainsAny(event.Server, "\r\n\x00") || strings.ContainsAny(event.Error, "\x00") {
		return errors.New("speedtest progress text is malformed")
	}
	if event.HelperAbsent && event.Phase != PhaseCleanup {
		return errors.New("only a cleanup event can report an absent lab helper")
	}
	if event.Phase == PhaseDone && event.DownloadMbps <= 0 {
		return errors.New("speedtest done event has no usable download result")
	}
	return nil
}

func clampError(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	runes := []rune(value)
	if len(runes) > maxErrorRunes {
		value = string(runes[:maxErrorRunes-1]) + "…"
	}
	if value == "" {
		value = "unknown speedtest failure"
	}
	return value
}
