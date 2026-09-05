// Package companion implements the fixed, read-only external lab console.
package companion

import (
	"errors"
	"sync"
	"time"
)

const (
	Healthy     = "healthy"
	Warning     = "warning"
	Failure     = "failure"
	Waiting     = "waiting"
	Disabled    = "disabled"
	Freshness   = 90 * time.Second
	HTTPAddress = "127.0.0.1:8765"
	SocketPath  = "/run/boetticher-companion/control.sock"
	ConfigPath  = "/etc/boetticher/companion.json"
)

type Config struct {
	PulseURL      string `json:"pulse_url"`
	CAFile        string `json:"ca_file"`
	EthernetMAC   string `json:"ethernet_mac"`
	Address       string `json:"address"`
	Gateway       string `json:"gateway"`
	DNS           string `json:"dns"`
	DNSName       string `json:"dns_name"`
	DNSAddress    string `json:"dns_address"`
	AgentID       string `json:"agent_id"`
	AgentHostname string `json:"agent_hostname"`
	Display       bool   `json:"display"`
	StreamDeck    bool   `json:"streamdeck"`
	PulseAgent    bool   `json:"pulse_agent"`
	Blinkt        bool   `json:"blinkt"`
	AirVPN        bool   `json:"airvpn"`
	Tailnet       bool   `json:"tailnet"`
}

type Item struct {
	ID         string    `json:"id"`
	Label      string    `json:"label"`
	Status     string    `json:"status"`
	Value      string    `json:"value"`
	Reason     string    `json:"reason"`
	ObservedAt time.Time `json:"observed_at"`
	Checks     []Item    `json:"checks,omitempty"`
}
type Resource struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Status     string    `json:"status"`
	CPU        *float64  `json:"cpu,omitempty"`
	Memory     *float64  `json:"memory,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}
type Snapshot struct {
	Version    int        `json:"version"`
	UpdatedAt  time.Time  `json:"updated_at"`
	Items      []Item     `json:"items"`
	Modules    []Item     `json:"modules"`
	LEDs       []Item     `json:"leds"`
	Resources  []Resource `json:"resources"`
	View       string     `json:"view"`
	Page       int        `json:"page"`
	Brightness string     `json:"brightness"`
	Display    bool       `json:"display"`
	StreamDeck bool       `json:"streamdeck"`
	Blinkt     bool       `json:"blinkt"`
	RenderedAt time.Time  `json:"rendered_at"`
	DeckAt     time.Time  `json:"deck_at"`
	BlinktAt   time.Time  `json:"blinkt_at"`
}
type State struct {
	mu      sync.Mutex
	data    Snapshot
	history []string
	Refresh chan struct{}
}

var itemIDs = []string{"pi", "link", "gateway", "dns", "proxmox", "pulse", "agent", "peripherals"}
var itemLabels = []string{"Pi health", "Lab link", "Gateway", "DNS", "Proxmox", "Pulse", "Agent reporting", "Local displays"}
var views = []string{"overview", "core", "resources", "pi"}

func NewState(c Config) *State {
	s := &State{Refresh: make(chan struct{}, 1), data: Snapshot{Version: 1, View: "overview", Brightness: "normal", Display: c.Display, StreamDeck: c.StreamDeck, Blinkt: c.Blinkt, Resources: []Resource{}}}
	for i, id := range itemIDs {
		s.data.Items = append(s.data.Items, Item{ID: id, Label: itemLabels[i], Status: Waiting, Reason: "Waiting for the first observation"})
	}
	if !c.PulseAgent {
		s.data.Items[6].Status = Disabled
		s.data.Items[6].Reason = "Pulse agent disabled"
	}
	if !c.Display && !c.StreamDeck {
		s.data.Items[7].Status = Disabled
		s.data.Items[7].Reason = "HDMI and StreamDeck disabled"
	}
	for _, module := range []struct {
		id, label string
		enabled   bool
	}{{"airvpn", "AirVPN", c.AirVPN}, {"tailnet-router", "Tailnet Router", c.Tailnet}} {
		status := Disabled
		if module.enabled {
			status = Waiting
		}
		s.data.Modules = append(s.data.Modules, Item{ID: module.id, Label: module.label, Status: status, Reason: "Module disabled"})
	}
	return s
}
func fresh(at, now time.Time) bool {
	return !at.IsZero() && now.Sub(at) <= Freshness && at.Sub(now) < 5*time.Second
}
func (s *State) Update(item Item) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, old := range s.data.Items {
		if old.ID == item.ID {
			item.Label = old.Label
			s.data.Items[i] = item
			return
		}
	}
	for i, old := range s.data.Modules {
		if old.ID == item.ID {
			item.Label = old.Label
			s.data.Modules[i] = item
			return
		}
	}
}
func (s *State) SetResources(resources []Resource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Resources = append([]Resource{}, resources...)
}
func (s *State) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	out := s.data
	out.UpdatedAt = now
	out.Items = append([]Item(nil), s.data.Items...)
	out.Modules = append([]Item(nil), s.data.Modules...)
	for i := range out.Modules {
		out.Modules[i].Checks = append([]Item(nil), out.Modules[i].Checks...)
		if out.Modules[i].Status != Disabled && !fresh(out.Modules[i].ObservedAt, now) {
			out.Modules[i].Status = Waiting
			out.Modules[i].Value = "No data"
			out.Modules[i].Reason = "No fresh module metrics from Pulse"
		}
		for j := range out.Modules[i].Checks {
			if !fresh(out.Modules[i].Checks[j].ObservedAt, now) {
				out.Modules[i].Checks[j].Status = Waiting
				out.Modules[i].Checks[j].Value = "No data"
			}
		}
		out.Modules[i].Status = assertedStatus(out.Modules[i].Status)
		for j := range out.Modules[i].Checks {
			out.Modules[i].Checks[j].Status = assertedStatus(out.Modules[i].Checks[j].Status)
		}
	}
	out.Resources = append([]Resource{}, s.data.Resources...)
	for i := range out.Items {
		if out.Items[i].Status != Disabled && !fresh(out.Items[i].ObservedAt, now) {
			out.Items[i].Status = Waiting
			out.Items[i].Value = "No data"
			out.Items[i].Reason = "No fresh observation; check the source connection"
		}
		out.Items[i].Status = assertedStatus(out.Items[i].Status)
	}
	for i := range out.Resources {
		if !fresh(out.Resources[i].ObservedAt, now) {
			out.Resources[i].Status = Waiting
			out.Resources[i].CPU = nil
			out.Resources[i].Memory = nil
		}
		out.Resources[i].Status = assertedStatus(out.Resources[i].Status)
	}
	if out.Display || out.StreamDeck {
		item := &out.Items[7]
		item.Status = Healthy
		item.Value = "Ready"
		item.Reason = "Enabled displays are updating"
		item.ObservedAt = now
		if out.Display && now.Sub(out.RenderedAt) > 10*time.Second {
			item.Status = Failure
			item.Value = "Not ready"
			item.Reason = "HDMI page has not reported a render in 10 seconds"
		}
		if out.StreamDeck && now.Sub(out.DeckAt) > 10*time.Second {
			item.Status = Failure
			item.Value = "Not ready"
			item.Reason = "StreamDeck is disconnected or not rendering"
		}
	}
	out.LEDs = append([]Item(nil), out.Items...)
	for i, module := range out.Modules {
		if module.Status != Disabled {
			out.LEDs[6+i] = module
		}
	}
	return out
}

// assertedStatus converts incomplete observations into the only two asserted
// operator outcomes. State retains Waiting internally so the renderer can
// preserve its precise reason, but no status command or display reports an
// indeterminate check as passing.
func assertedStatus(status string) string {
	if status == Waiting {
		return Failure
	}
	return status
}

// Action accepts only presentation changes; there is no command execution path.
func (s *State) Action(action, target string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	validTarget := target == "overview" || target == "core" || target == "resources"
	for _, id := range itemIDs {
		validTarget = validTarget || target == id
	}
	for _, module := range s.data.Modules {
		validTarget = validTarget || target == module.ID
	}
	for _, resource := range s.data.Resources {
		validTarget = validTarget || target == "resource:"+resource.ID
	}
	switch action {
	case "select":
		if !validTarget {
			return errors.New("unknown view")
		}
	case "home", "back", "previous", "next", "dim", "refresh":
		if target != "" {
			return errors.New("action does not take a target")
		}
	default:
		return errors.New("unsupported local action")
	}
	if s.data.Brightness == "blank" {
		s.data.Brightness = "normal"
		return nil
	}
	old := s.data.View
	switch action {
	case "select":
		s.data.View = target
		s.data.Page = 0
	case "home":
		s.data.View = "overview"
		s.data.Page = 0
		s.history = nil
	case "back":
		if len(s.history) > 0 {
			s.data.View = s.history[len(s.history)-1]
			s.history = s.history[:len(s.history)-1]
		} else {
			s.data.View = "overview"
		}
		s.data.Page = 0
	case "next", "previous":
		step := 1
		if action == "previous" {
			step = -1
		}
		if s.data.View == "resources" {
			pages := (len(s.data.Resources) + 7) / 8
			if pages < 1 {
				pages = 1
			}
			s.data.Page = (s.data.Page + step + pages) % pages
		} else {
			index := 0
			for i, v := range views {
				if v == s.data.View {
					index = i
				}
			}
			s.data.View = views[(index+step+len(views))%len(views)]
			s.data.Page = 0
		}
	case "dim":
		if s.data.Brightness == "normal" {
			s.data.Brightness = "dim"
		} else {
			s.data.Brightness = "blank"
		}
	case "refresh":
		select {
		case s.Refresh <- struct{}{}:
		default:
		}
	}
	if s.data.View != old && action != "home" && action != "back" {
		if len(s.history) >= 16 {
			s.history = s.history[1:]
		}
		s.history = append(s.history, old)
	}
	return nil
}
func (s *State) Heartbeat(device string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	switch device {
	case "display":
		s.data.RenderedAt = now
	case "streamdeck":
		s.data.DeckAt = now
	case "blinkt":
		s.data.BlinktAt = now
	default:
		return errors.New("unknown display")
	}
	return nil
}
