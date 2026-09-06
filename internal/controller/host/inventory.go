package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Node struct {
	Node   string `json:"node"`
	Status string `json:"status"`
	Type   string `json:"type"`
}

type Guest struct {
	VMID   int    `json:"vmid"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Status string `json:"status"`
	Node   string `json:"node"`
}

type Storage struct {
	ID      string `json:"storage"`
	Type    string `json:"type"`
	Active  int    `json:"active"`
	Content string `json:"content"`
	Path    string `json:"path"`
}

type Inventory struct {
	Hostname     string
	Version      string
	Architecture string
	Nodes        []Node
	Guests       []Guest
	Storage      []Storage
	Services     map[string]string
	Disks        json.RawMessage
	Mounts       json.RawMessage
	Links        json.RawMessage
	Addresses    json.RawMessage
	Routes       json.RawMessage
	PVs          json.RawMessage
	VGs          json.RawMessage
	LVs          json.RawMessage
	ByID         string
	OptionalErrs []string
}

const (
	cmdHostname = "hostname"
	cmdVersion  = "pveversion"
	cmdArch     = "dpkg --print-architecture"
	cmdPvesh    = "command -v pvesh"
	cmdNodes    = "pvesh get /nodes --output-format json"
	cmdGuests   = "pvesh get /cluster/resources --output-format json"
	cmdStorage  = "pvesh get /storage --output-format json"
)

func Enroll(ctx context.Context, transport Transport) (LabConfig, Inventory, error) {
	if _, _, err := CreateIdentity(ctx, nil); err != nil {
		return LabConfig{}, Inventory{}, fmt.Errorf("controller identity: %w", err)
	}
	if _, err := readKnownHosts(); err != nil {
		return LabConfig{}, Inventory{}, err
	}
	core, err := collectCore(ctx, transport)
	if err != nil {
		return LabConfig{}, Inventory{}, err
	}
	if len(core.Nodes) != 1 {
		return LabConfig{}, Inventory{}, fmt.Errorf("expected exactly one standalone Proxmox node, found %d", len(core.Nodes))
	}
	if core.Nodes[0].Type != "" && core.Nodes[0].Type != "node" {
		return LabConfig{}, Inventory{}, fmt.Errorf("Proxmox endpoint is not a standalone node")
	}
	if core.Nodes[0].Node == "" || core.Nodes[0].Status == "offline" {
		return LabConfig{}, Inventory{}, errors.New("Proxmox node identity is incomplete or offline")
	}
	if !supportedVersion(core.Version) {
		return LabConfig{}, Inventory{}, fmt.Errorf("unsupported Proxmox version %q", core.Version)
	}
	if core.Architecture != "amd64" && core.Architecture != "arm64" {
		return LabConfig{}, Inventory{}, fmt.Errorf("unsupported Proxmox architecture %q", core.Architecture)
	}
	config := LabConfig{Name: "home-lab", Proxmox: ProxmoxConfig{Address: transport.Address, User: "root", Node: core.Nodes[0].Node, Repository: "no-subscription"}}
	if existing, err := LoadConfig(); err == nil {
		if existing.Proxmox.Address != config.Proxmox.Address || existing.Proxmox.User != config.Proxmox.User || existing.Proxmox.Node != config.Proxmox.Node {
			return LabConfig{}, Inventory{}, errors.New("existing Proxmox enrollment binding does not match this verified host")
		}
		return existing, core, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		// A malformed or inaccessible configuration must not be silently replaced.
		return LabConfig{}, Inventory{}, err
	}
	if err := SaveConfig(config); err != nil {
		return LabConfig{}, Inventory{}, err
	}
	return config, core, nil
}

func readKnownHosts() ([]byte, error) {
	data, err := os.ReadFile(KnownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("read controller known-hosts: %w", err)
	}
	if strings.TrimSpace(string(data)) == "" {
		return nil, errors.New("controller known-hosts is empty; import the trusted Proxmox key first")
	}
	return data, nil
}

func collectCore(ctx context.Context, transport Transport) (Inventory, error) {
	var result Inventory
	for _, item := range []struct {
		command string
		dest    *string
	}{{cmdHostname, &result.Hostname}, {cmdVersion, &result.Version}, {cmdArch, &result.Architecture}} {
		output, err := transport.Run(ctx, item.command)
		if err != nil {
			return Inventory{}, fmt.Errorf("%s: %w", item.command, err)
		}
		*item.dest = strings.TrimSpace(string(output.Stdout))
	}
	if _, err := transport.Run(ctx, cmdPvesh); err != nil {
		return Inventory{}, fmt.Errorf("pvesh is unavailable: %w", err)
	}
	nodesOutput, err := transport.Run(ctx, cmdNodes)
	if err != nil {
		return Inventory{}, fmt.Errorf("read Proxmox nodes: %w", err)
	}
	result.Nodes, err = parseNodes(nodesOutput.Stdout)
	if err != nil {
		return Inventory{}, err
	}
	return result, nil
}

func Collect(ctx context.Context, transport Transport, details bool) (Inventory, error) {
	result, err := collectCore(ctx, transport)
	if err != nil {
		return Inventory{}, err
	}
	result.Services = map[string]string{}
	for _, service := range []string{"pve-cluster", "pvedaemon", "pvestatd", "pveproxy"} {
		output, runErr := transport.Run(ctx, "systemctl is-active "+service+" || true")
		if runErr == nil {
			result.Services[service] = strings.TrimSpace(string(output.Stdout))
		}
	}
	for _, item := range []struct {
		command string
		set     func(json.RawMessage)
	}{{cmdGuests, func(value json.RawMessage) { result.Guests = parseGuests(value) }}, {cmdStorage, func(value json.RawMessage) { result.Storage = parseStorage(value) }}} {
		output, runErr := transport.Run(ctx, item.command)
		if runErr != nil {
			return Inventory{}, fmt.Errorf("%s: %w", item.command, runErr)
		}
		item.set(output.Stdout)
	}
	if len(result.Nodes) == 1 && safeIdentifier(result.Nodes[0].Node) {
		output, runErr := transport.Run(ctx, "pvesh get /nodes/"+result.Nodes[0].Node+"/storage --output-format json")
		if runErr == nil {
			result.Storage = parseStorage(output.Stdout)
		}
	}
	if !details {
		return result, nil
	}
	optional := []struct {
		command string
		set     func([]byte)
	}{{"lsblk --json -o NAME,KNAME,PATH,MODEL,SERIAL,WWN,SIZE,TYPE,TRAN,PKNAME,PTTYPE,FSTYPE,MOUNTPOINTS", func(v []byte) { result.Disks = json.RawMessage(v) }}, {"findmnt --json", func(v []byte) { result.Mounts = json.RawMessage(v) }}, {"ip -json link", func(v []byte) { result.Links = json.RawMessage(v) }}, {"ip -json address", func(v []byte) { result.Addresses = json.RawMessage(v) }}, {"ip -json route", func(v []byte) { result.Routes = json.RawMessage(v) }}, {"pvs --reportformat json", func(v []byte) { result.PVs = json.RawMessage(v) }}, {"vgs --reportformat json", func(v []byte) { result.VGs = json.RawMessage(v) }}, {"lvs --reportformat json", func(v []byte) { result.LVs = json.RawMessage(v) }}, {"find /dev/disk/by-id -maxdepth 1 -type l -printf '%f -> %p\\n'", func(v []byte) { result.ByID = string(v) }}}
	for _, item := range optional {
		output, runErr := transport.Run(ctx, item.command)
		if runErr != nil {
			result.OptionalErrs = append(result.OptionalErrs, item.command+": "+runErr.Error())
			continue
		}
		item.set(output.Stdout)
	}
	return result, nil
}

func parseNodes(data []byte) ([]Node, error) {
	var nodes []Node
	if err := json.Unmarshal(data, &nodes); err == nil {
		return nodes, nil
	}
	var envelope struct {
		Data []Node `json:"data"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil || envelope.Data == nil {
		return nil, errors.New("decode Proxmox node listing")
	}
	return envelope.Data, nil
}

func parseGuests(data []byte) []Guest {
	var raw []map[string]any
	if json.Unmarshal(data, &raw) != nil {
		var envelope struct {
			Data []map[string]any `json:"data"`
		}
		if json.Unmarshal(data, &envelope) != nil {
			return nil
		}
		raw = envelope.Data
	}
	guests := make([]Guest, 0)
	for _, item := range raw {
		kind, _ := item["type"].(string)
		if kind != "qemu" && kind != "lxc" {
			continue
		}
		guests = append(guests, Guest{VMID: number(item["vmid"]), Name: stringValue(item["name"]), Type: kind, Status: stringValue(item["status"]), Node: stringValue(item["node"])})
	}
	return guests
}

func parseStorage(data []byte) []Storage {
	var storage []Storage
	if json.Unmarshal(data, &storage) == nil {
		return storage
	}
	var envelope struct {
		Data []Storage `json:"data"`
	}
	_ = json.Unmarshal(data, &envelope)
	return envelope.Data
}

func number(value any) int {
	switch v := value.(type) {
	case float64:
		return int(v)
	case json.Number:
		n, _ := strconv.Atoi(string(v))
		return n
	case int:
		return v
	default:
		return 0
	}
}

func stringValue(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}

func supportedVersion(value string) bool {
	if !strings.HasPrefix(value, "pve-manager/") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(value, "pve-manager/"), ".")
	if len(parts) == 0 {
		return false
	}
	major, err := strconv.Atoi(parts[0])
	return err == nil && major >= 8
}
