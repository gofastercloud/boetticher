package controllerstatus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

// ProxmoxSnapshot is the detailed, read-only data surface used by the
// Controller's StreamDeck. It is deliberately separate from StatusSnapshot,
// which remains the fixed coarse Blinkt contract.
type ProxmoxSnapshot struct {
	Host      ProxmoxHostStats
	Storage   []StorageStats
	Guests    []GuestStats
	FetchedAt time.Time
	Stale     bool
	Error     string
}

type ProxmoxHostStats struct {
	Node        string
	Version     string
	CPUPercent  float64
	MemoryUsed  uint64
	MemoryTotal uint64
	Uptime      time.Duration
}

type StorageStats struct {
	Name    string
	Used    uint64
	Total   uint64
	Percent float64
}

type GuestStats struct {
	VMID        int
	Name        string
	Kind        string
	Status      string
	CPUPercent  float64
	MemoryUsed  uint64
	MemoryTotal uint64
	Uptime      time.Duration
}

type HostCommandRunner func(context.Context, controllerhost.Transport, string) (controllerhost.Result, error)

type ProxmoxCollector struct {
	LoadConfig func() (controllerhost.LabConfig, error)
	Transport  func(controllerhost.LabConfig) (controllerhost.Transport, error)
	Run        HostCommandRunner
	Now        func() time.Time
}

func (c ProxmoxCollector) Collect(ctx context.Context) (ProxmoxSnapshot, error) {
	load := c.LoadConfig
	if load == nil {
		load = controllerhost.LoadConfig
	}
	config, err := load()
	if errors.Is(err, os.ErrNotExist) || (err == nil && config.Proxmox.Node == "") {
		return ProxmoxSnapshot{}, errors.New("Host not enrolled")
	}
	if err != nil {
		return ProxmoxSnapshot{}, fmt.Errorf("read Host configuration: %w", err)
	}
	transportFor := c.Transport
	if transportFor == nil {
		transportFor = controllerhost.TransportFor
	}
	transport, err := transportFor(config)
	if err != nil {
		return ProxmoxSnapshot{}, fmt.Errorf("configure Host transport: %w", err)
	}
	transport.Timeout = 10 * time.Second
	run := c.Run
	if run == nil {
		run = func(ctx context.Context, transport controllerhost.Transport, command string) (controllerhost.Result, error) {
			return transport.Run(ctx, command)
		}
	}
	quote := func(value string) string {
		return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
	}
	node := quote(config.Proxmox.Node)
	commands := []struct {
		name string
		cmd  string
	}{
		{"node status", "pvesh get /nodes/" + node + "/status --output-format json"},
		{"storage", "pvesh get /nodes/" + node + "/storage --output-format json"},
		{"guests", "pvesh get /cluster/resources --type vm --output-format json"},
	}
	outputs := make([][]byte, len(commands))
	for index, command := range commands {
		result, runErr := run(ctx, transport, command.cmd)
		if runErr != nil {
			return ProxmoxSnapshot{}, fmt.Errorf("collect Host %s: %w", command.name, runErr)
		}
		outputs[index] = result.Stdout
	}
	host, err := parseProxmoxHost(outputs[0], config.Proxmox.Node)
	if err != nil {
		return ProxmoxSnapshot{}, fmt.Errorf("parse Host telemetry: %w", err)
	}
	storage, err := parseProxmoxStorage(outputs[1])
	if err != nil {
		return ProxmoxSnapshot{}, fmt.Errorf("parse Host storage telemetry: %w", err)
	}
	guests, err := parseProxmoxGuests(outputs[2])
	if err != nil {
		return ProxmoxSnapshot{}, fmt.Errorf("parse Host guest telemetry: %w", err)
	}
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	return ProxmoxSnapshot{Host: host, Storage: storage, Guests: guests, FetchedAt: now}, nil
}

func parseProxmoxHost(data []byte, fallbackNode string) (ProxmoxHostStats, error) {
	var raw struct {
		Node       string  `json:"node"`
		Version    string  `json:"pveversion"`
		CPU        float64 `json:"cpu"`
		MemoryUsed uint64  `json:"mem"`
		MemoryMax  uint64  `json:"maxmem"`
		Memory     struct {
			Used  uint64 `json:"used"`
			Total uint64 `json:"total"`
		} `json:"memory"`
		Uptime uint64 `json:"uptime"`
	}
	if err := decodeProxmoxObject(data, &raw); err != nil {
		return ProxmoxHostStats{}, err
	}
	node := strings.TrimSpace(raw.Node)
	if node == "" {
		node = fallbackNode
	}
	if node == "" {
		return ProxmoxHostStats{}, errors.New("node name is missing")
	}
	if raw.MemoryUsed == 0 {
		raw.MemoryUsed = raw.Memory.Used
	}
	if raw.MemoryMax == 0 {
		raw.MemoryMax = raw.Memory.Total
	}
	return ProxmoxHostStats{
		Node:        node,
		Version:     strings.TrimSpace(raw.Version),
		CPUPercent:  normalizeCPU(raw.CPU),
		MemoryUsed:  raw.MemoryUsed,
		MemoryTotal: raw.MemoryMax,
		Uptime:      time.Duration(raw.Uptime) * time.Second,
	}, nil
}

func parseProxmoxStorage(data []byte) ([]StorageStats, error) {
	var raw []struct {
		Name  string `json:"storage"`
		Used  uint64 `json:"used"`
		Total uint64 `json:"total"`
	}
	if err := decodeProxmoxList(data, &raw); err != nil {
		return nil, err
	}
	storage := make([]StorageStats, 0, len(raw))
	for _, item := range raw {
		name := strings.TrimSpace(item.Name)
		if name == "" {
			return nil, errors.New("storage name is missing")
		}
		percent := 0.0
		if item.Total > 0 {
			percent = float64(item.Used) * 100 / float64(item.Total)
		}
		storage = append(storage, StorageStats{Name: name, Used: item.Used, Total: item.Total, Percent: percent})
	}
	sort.Slice(storage, func(i, j int) bool { return storage[i].Name < storage[j].Name })
	return storage, nil
}

func parseProxmoxGuests(data []byte) ([]GuestStats, error) {
	var raw []struct {
		VMID      int     `json:"vmid"`
		Name      string  `json:"name"`
		Kind      string  `json:"type"`
		Status    string  `json:"status"`
		CPU       float64 `json:"cpu"`
		Memory    uint64  `json:"mem"`
		MaxMemory uint64  `json:"maxmem"`
		Uptime    uint64  `json:"uptime"`
	}
	if err := decodeProxmoxList(data, &raw); err != nil {
		return nil, err
	}
	guests := make([]GuestStats, 0, len(raw))
	for _, item := range raw {
		if item.VMID <= 0 {
			return nil, errors.New("guest VMID is invalid")
		}
		name := strings.TrimSpace(item.Name)
		if name == "" {
			return nil, fmt.Errorf("guest %d name is missing", item.VMID)
		}
		kind, err := guestKind(item.Kind)
		if err != nil {
			return nil, fmt.Errorf("guest %d: %w", item.VMID, err)
		}
		guests = append(guests, GuestStats{
			VMID:        item.VMID,
			Name:        name,
			Kind:        kind,
			Status:      strings.TrimSpace(item.Status),
			CPUPercent:  normalizeCPU(item.CPU),
			MemoryUsed:  item.Memory,
			MemoryTotal: item.MaxMemory,
			Uptime:      time.Duration(item.Uptime) * time.Second,
		})
	}
	sort.Slice(guests, func(i, j int) bool { return guests[i].VMID < guests[j].VMID })
	return guests, nil
}

func guestKind(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "lxc", "container":
		return "lxc", nil
	case "qemu", "vm":
		return "vm", nil
	default:
		return "", fmt.Errorf("unsupported guest type %q", value)
	}
}

func normalizeCPU(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value <= 1 {
		value *= 100
	}
	if value > 100 {
		return 100
	}
	return value
}

func decodeProxmoxObject(data []byte, target any) error {
	var raw json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("empty response")
	}
	if raw[0] == '{' {
		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(raw, &envelope); err == nil {
			if data, ok := envelope["data"]; ok {
				if len(data) == 0 || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
					return errors.New("response data is empty")
				}
				return json.Unmarshal(data, target)
			}
		}
	}
	return json.Unmarshal(raw, target)
}

func decodeProxmoxList(data []byte, target any) error {
	var raw json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("empty response")
	}
	if raw[0] == '{' {
		var envelope struct {
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			return err
		}
		if len(envelope.Data) == 0 || bytes.Equal(bytes.TrimSpace(envelope.Data), []byte("null")) {
			return errors.New("response data is missing")
		}
		return json.Unmarshal(envelope.Data, target)
	}
	return json.Unmarshal(raw, target)
}
