package firewall

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type Counter struct {
	Rule    string `json:"rule"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// ParseCounters extracts only named boetticher rule counters from nft JSON.
// It intentionally ignores anonymous or unrelated operator counters.
func ParseCounters(data []byte) ([]Counter, error) {
	var document struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("decode nftables JSON: %w", err)
	}
	result := make([]Counter, 0)
	for _, object := range document.NFTables {
		raw, ok := object["rule"]
		if !ok {
			continue
		}
		var rule map[string]any
		if err := json.Unmarshal(raw, &rule); err != nil {
			return nil, fmt.Errorf("decode nftables rule: %w", err)
		}
		comment, _ := rule["comment"].(string)
		if !strings.HasPrefix(comment, "boetticher:") {
			continue
		}
		packets, bytes, found := findCounter(rule)
		if found {
			result = append(result, Counter{Rule: comment, Packets: packets, Bytes: bytes})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Rule < result[j].Rule })
	return result, nil
}

func findCounter(value any) (uint64, uint64, bool) {
	switch typed := value.(type) {
	case map[string]any:
		if raw, ok := typed["counter"].(map[string]any); ok {
			packets, packetsOK := numberValue(raw["packets"])
			bytes, bytesOK := numberValue(raw["bytes"])
			if packetsOK && bytesOK {
				return packets, bytes, true
			}
		}
		for _, child := range typed {
			if packets, bytes, ok := findCounter(child); ok {
				return packets, bytes, true
			}
		}
	case []any:
		for _, child := range typed {
			if packets, bytes, ok := findCounter(child); ok {
				return packets, bytes, true
			}
		}
	}
	return 0, 0, false
}

func numberValue(value any) (uint64, bool) {
	number, ok := value.(float64)
	if !ok || number < 0 || number != float64(uint64(number)) {
		return 0, false
	}
	return uint64(number), true
}
