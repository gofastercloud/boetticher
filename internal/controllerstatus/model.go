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
	Controller     Component
	Host           Component
	Firewall       Component
	DNS            Component
	DHCP           Component
	Internet       InternetStatus
	Configuration  Component
	RebootRequired Component
}

func NewSnapshot(hostConfigured bool) StatusSnapshot {
	host := Component{State: Off, Detail: "Host not enrolled"}
	if hostConfigured {
		host = Component{State: Checking, Detail: "Establishing Host state"}
	}
	return StatusSnapshot{
		Controller:     Component{State: Checking, Detail: "Establishing Controller state"},
		Host:           host,
		Firewall:       Component{State: Off, Detail: "Firewall capability not configured"},
		DNS:            Component{State: Off, Detail: "DNS capability not configured"},
		DHCP:           Component{State: Off, Detail: "DHCP capability not configured"},
		Internet:       InternetStatus{Component: Component{State: Checking, Detail: "Checking Internet connectivity"}},
		Configuration:  Component{State: Off},
		RebootRequired: Component{State: Off},
	}
}

type OperationEvent struct {
	Event               string `json:"event"`
	Name                string `json:"name"`
	CurrentStep         int    `json:"current_step,omitempty"`
	TotalSteps          int    `json:"total_steps,omitempty"`
	Steps               int    `json:"steps,omitempty"`
	Detail              string `json:"detail,omitempty"`
	ConfigurationFailed bool   `json:"configuration_failed,omitempty"`
}

func (e OperationEvent) totalSteps() int {
	if e.TotalSteps > 0 {
		return e.TotalSteps
	}
	return e.Steps
}
