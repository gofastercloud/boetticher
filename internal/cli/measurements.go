package cli

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/gofastercloud/boetticher/internal/telemetry"
)

type measurementBucket struct {
	Count      int   `json:"count"`
	Failures   int   `json:"failures,omitempty"`
	Changed    int   `json:"changed,omitempty"`
	DurationMS int64 `json:"duration_ms"`
}

type measurementSummary struct {
	Count      int                          `json:"count"`
	Failures   int                          `json:"failures,omitempty"`
	Changed    int                          `json:"changed,omitempty"`
	DurationMS int64                        `json:"duration_ms"`
	ByKey      map[string]measurementBucket `json:"by_key,omitempty"`
}

type operationMeasurements struct {
	ProxmoxAPI  measurementSummary `json:"proxmox_api"`
	ProviderAPI measurementSummary `json:"provider_api"`
	SSH         measurementSummary `json:"ssh"`
	Ansible     measurementSummary `json:"ansible"`
}

func (m *operationMeasurements) Observe(event telemetry.Event) {
	if m == nil || event.Category == "" || event.Duration < 0 {
		return
	}
	var summary *measurementSummary
	switch event.Category {
	case "proxmox_api":
		summary = &m.ProxmoxAPI
	case "provider_api":
		summary = &m.ProviderAPI
	case "ssh":
		summary = &m.SSH
	case "ansible":
		summary = &m.Ansible
	default:
		return
	}
	if summary.ByKey == nil {
		summary.ByKey = make(map[string]measurementBucket)
	}
	summary.Count++
	if !event.Success {
		summary.Failures++
	}
	if event.Changed {
		summary.Changed++
	}
	durationMS := event.Duration.Milliseconds()
	summary.DurationMS += durationMS
	key := measurementKey(event)
	bucket := summary.ByKey[key]
	bucket.Count++
	if !event.Success {
		bucket.Failures++
	}
	if event.Changed {
		bucket.Changed++
	}
	bucket.DurationMS += durationMS
	summary.ByKey[key] = bucket
}

func measurementKey(event telemetry.Event) string {
	if event.Category == "proxmox_api" {
		status := strconv.Itoa(event.Status)
		if event.Status == 0 {
			status = "transport_error"
		}
		return strings.TrimSpace(strings.Join([]string{event.Method, normalizeProxmoxEndpoint(event.Operation), status}, " "))
	}
	return strings.TrimSpace(strings.Join([]string{event.Operation, event.Target}, " "))
}

func normalizeProxmoxEndpoint(endpoint string) string {
	parts := strings.Split(path.Clean("/"+endpoint), "/")
	for index, part := range parts {
		if part == "" {
			continue
		}
		if isDecimal(part) || strings.HasPrefix(part, "UPID:") {
			parts[index] = "{id}"
		}
	}
	return strings.Join(parts, "/")
}

func isDecimal(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func (m operationMeasurements) summaryLine() string {
	return fmt.Sprintf("Measured operations: Proxmox API %d (%dms), Provider API %d (%dms), SSH %d (%dms), Ansible %d (%dms)",
		m.ProxmoxAPI.Count, m.ProxmoxAPI.DurationMS, m.ProviderAPI.Count, m.ProviderAPI.DurationMS, m.SSH.Count, m.SSH.DurationMS, m.Ansible.Count, m.Ansible.DurationMS)
}
