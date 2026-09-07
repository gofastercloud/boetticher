// Package controllerstatus contains the small, in-memory status model used by
// the Controller's operator display.
package controllerstatus

import "time"

// State is intentionally small. It is a display state, not qualification or
// evidence state.
type State string

const (
	Off       State = "off"
	Checking  State = "checking"
	Healthy   State = "healthy"
	Attention State = "attention"
	Failed    State = "failed"
)

type Component struct {
	State  State
	Detail string
}

type InternetStatus struct {
	Component
	ThroughputMbps float64
	ThroughputAt   time.Time
}

// StatusSnapshot is the fixed Controller display contract. Keep the order and
// names stable: they are the physical reference-lab UX.
type StatusSnapshot struct {
	Controller        Component
	Host              Component
	Firewall          Component
	DNS               Component
	DHCPNTP           Component
	Internet          InternetStatus
	HostUpdates       Component
	ControllerUpdates Component
}

func NewSnapshot(hostConfigured bool) StatusSnapshot {
	host := Component{State: Off, Detail: "Host not enrolled"}
	if hostConfigured {
		host = Component{State: Checking, Detail: "Establishing Host state"}
	}
	return StatusSnapshot{
		Controller:        Component{State: Checking, Detail: "Establishing Controller state"},
		Host:              host,
		Firewall:          Component{State: Off, Detail: "Firewall capability not configured"},
		DNS:               Component{State: Off, Detail: "DNS capability not configured"},
		DHCPNTP:           Component{State: Off, Detail: "DHCP/NTP capabilities not configured"},
		Internet:          InternetStatus{Component: Component{State: Checking, Detail: "Checking Internet connectivity"}},
		HostUpdates:       Component{State: Checking, Detail: "Checking Host update state"},
		ControllerUpdates: Component{State: Checking, Detail: "Checking Controller update state"},
	}
}

type OperationEvent struct {
	Event       string `json:"event"`
	Name        string `json:"name"`
	CurrentStep int    `json:"current_step,omitempty"`
	TotalSteps  int    `json:"total_steps,omitempty"`
	Steps       int    `json:"steps,omitempty"`
	Detail      string `json:"detail,omitempty"`
	Staged      bool   `json:"staged,omitempty"`
}

func (e OperationEvent) totalSteps() int {
	if e.TotalSteps > 0 {
		return e.TotalSteps
	}
	return e.Steps
}
