// Package tailnet implements the reference LAB subnet-router contract.
package tailnet

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	Module        = "tailnet"
	GuestName     = "lab-tailnet-01"
	GuestVMID     = 200
	GuestAddress  = "10.10.5.10"
	Gateway       = "10.10.5.1"
	Resolver      = Gateway
	VLAN          = 5
	Route         = "10.10.0.0/16"
	GuestMAC      = "02:00:00:00:05:10"
	OwnerTag      = "boetticher-module-tailnet"
	Version       = "1.102.3"
	PackageSHA256 = "88e1b0319da94a52ea409a1a5935e4e7215065a25cd99bc509b6dcbb73737fae"
	ImageContract = "tailnet-v1"
)

type State string

const (
	Off       State = "off"
	Checking  State = "checking"
	Healthy   State = "healthy"
	Attention State = "attention"
	Failed    State = "failed"
)

// Report is shared by the native CLI and the Controller display adapter.
// Healthy describes observed local operation, never a remote packet journey.
type Report struct {
	Configured bool      `json:"configured"`
	State      State     `json:"state"`
	Detail     string    `json:"detail"`
	ObservedAt time.Time `json:"observed_at"`
	NeedsAuth  bool      `json:"needs_auth,omitempty"`
}

func NewReport(configured bool, state State, detail string) Report {
	return Report{Configured: configured, State: state, Detail: detail, ObservedAt: time.Now().UTC()}
}

type nativeStatus struct {
	Version      string
	BackendState string
	TUN          *bool
	Self         *struct {
		Online        *bool
		Expired       bool
		KeyExpiry     *time.Time
		PrimaryRoutes []string
		AllowedIPs    []string
	}
	ExitNodeStatus json.RawMessage
	Health         []string
}
type nativePrefs struct {
	AdvertiseRoutes []string
	NoSNAT          *bool
	RouteAll        *bool
	CorpDNS         *bool
	WantRunning     *bool
	ExitNodeID      *string
	ExitNodeIP      *string
	RunSSH          *bool
}

func exactPreferences(data []byte) bool {
	var p nativePrefs
	if json.Unmarshal(data, &p) != nil || p.NoSNAT == nil || p.RouteAll == nil || p.CorpDNS == nil || p.WantRunning == nil || p.ExitNodeID == nil || p.ExitNodeIP == nil {
		return false
	}
	return len(p.AdvertiseRoutes) == 1 && p.AdvertiseRoutes[0] == Route &&
		!*p.NoSNAT && !*p.RouteAll && !*p.CorpDNS && *p.WantRunning &&
		*p.ExitNodeID == "" && *p.ExitNodeIP == "" && p.RunSSH != nil && !*p.RunSSH
}

// ParseNative uses the separate native status and preferences responses.
// Neither an omitted preference nor the existence of a running guest proves health.
func ParseNative(status, prefs []byte) (Report, error) {
	var s nativeStatus
	if err := json.Unmarshal(status, &s); err != nil || s.BackendState == "" {
		return NewReport(true, Failed, "Malformed native Tailnet status"), errors.New("invalid native Tailnet status")
	}
	switch s.BackendState {
	case "NeedsLogin":
		r := NewReport(true, Attention, "Tailnet enrollment or reauthentication required")
		r.NeedsAuth = true
		return r, nil
	case "NeedsMachineAuth":
		return NewReport(true, Attention, "Approve this device in Tailscale administration"), nil
	case "Starting", "NoState":
		return NewReport(true, Checking, "Tailscale backend is starting"), nil
	case "Stopped":
		return NewReport(true, Failed, "Tailscale backend is stopped; run module tailnet apply"), nil
	case "Running":
	default:
		return NewReport(true, Failed, "Unknown Tailscale backend state"), nil
	}
	if s.Self == nil || s.Self.Online == nil || s.TUN == nil || !*s.TUN {
		return NewReport(true, Failed, "Native Tailnet identity or kernel TUN evidence is missing"), nil
	}
	if s.Self.Expired || (s.Self.KeyExpiry != nil && !s.Self.KeyExpiry.IsZero() && time.Now().After(*s.Self.KeyExpiry)) {
		r := NewReport(true, Attention, "Tailnet node identity expired; reauthenticate")
		r.NeedsAuth = true
		return r, nil
	}
	if !*s.Self.Online {
		return NewReport(true, Failed, "Tailnet is disconnected from its coordination service"), nil
	}
	if !(s.Version == Version || strings.HasPrefix(s.Version, Version+"-")) {
		return NewReport(true, Attention, fmt.Sprintf("Tailscale %s is required; reconcile the router version", Version)), nil
	}
	if !exactPreferences(prefs) || (len(s.ExitNodeStatus) > 0 && string(s.ExitNodeStatus) != "null") {
		return NewReport(true, Failed, "Tailnet route, SNAT, DNS or exit-node preferences do not match intent"), nil
	}
	if len(s.Health) > 0 {
		// Native diagnostics can contain URLs or identities. Do not project them.
		return NewReport(true, Attention, "Tailscale reports a native health warning; inspect locally"), nil
	}
	approved := false
	for _, route := range append(s.Self.PrimaryRoutes, s.Self.AllowedIPs...) {
		if route == Route {
			approved = true
		}
	}
	if !approved {
		return NewReport(true, Attention, "LAB route approval is pending or not observable"), nil
	}
	return NewReport(true, Healthy, "Tailnet local runtime and approved LAB route verified; remote access and split DNS are separate acceptance checks"), nil
}
