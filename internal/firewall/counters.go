package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

const (
	MaxNFTJSONBytes = 4 << 20
	MaxNFTObjects   = 4096
	MaxNFTComment   = 256
	MaxNFTCounters  = 2048
)

type Counter struct {
	Rule    string `json:"rule"`
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Family  string `json:"family"`
	Table   string `json:"table"`
	Chain   string `json:"chain"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type NFTSnapshot struct {
	Counters         []Counter `json:"counters"`
	Fingerprint      string    `json:"fingerprint"`
	OwnedObjectCount int       `json:"owned_object_count"`
}

// ParseCounters extracts only semantic, commented counters from the two
// boetticher-owned nftables tables. Handles, ordering, and operator rules are
// intentionally not part of this contract.
func ParseCounters(data []byte) ([]Counter, error) {
	snapshot, err := ParseNFTSnapshot(data)
	if err != nil {
		return nil, err
	}
	return snapshot.Counters, nil
}

// ParseNFTSnapshot parses bounded nft JSON and returns both counters and a
// deterministic fingerprint of the owned ruleset structure. Counter values and
// nft rule handles are removed from the fingerprint; semantic comments and
// expressions remain structural evidence.
func ParseNFTSnapshot(data []byte) (NFTSnapshot, error) {
	if len(data) == 0 {
		return NFTSnapshot{}, fmt.Errorf("nftables JSON is empty")
	}
	if len(data) > MaxNFTJSONBytes {
		return NFTSnapshot{}, fmt.Errorf("nftables JSON exceeds %d bytes", MaxNFTJSONBytes)
	}
	var document struct {
		NFTables json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return NFTSnapshot{}, fmt.Errorf("decode nftables JSON: %w", err)
	}
	if len(document.NFTables) == 0 || string(document.NFTables) == "null" {
		return NFTSnapshot{}, fmt.Errorf("nftables JSON has no nftables array")
	}
	var objects []json.RawMessage
	if err := json.Unmarshal(document.NFTables, &objects); err != nil {
		return NFTSnapshot{}, fmt.Errorf("decode nftables objects: %w", err)
	}
	if len(objects) > MaxNFTObjects {
		return NFTSnapshot{}, fmt.Errorf("nftables object count exceeds %d", MaxNFTObjects)
	}

	owned := make([]normalizedObject, 0)
	counters := make([]Counter, 0)
	seenCounterIDs := make(map[string]struct{})
	for index, rawObject := range objects {
		object, err := decodeObject(rawObject)
		if err != nil {
			return NFTSnapshot{}, fmt.Errorf("decode nftables object %d: %w", index, err)
		}
		if rawTable, ok := object["table"]; ok {
			table, err := decodeTable(rawTable)
			if err != nil {
				return NFTSnapshot{}, fmt.Errorf("decode nftables table: %w", err)
			}
			if isOwnedTable(table.Family, table.Name) {
				owned = append(owned, normalizeOwnedObject("table", object))
			}
			continue
		}
		if rawChain, ok := object["chain"]; ok {
			chain, err := decodeChain(rawChain)
			if err != nil {
				return NFTSnapshot{}, fmt.Errorf("decode nftables chain: %w", err)
			}
			if isOwnedTable(chain.Family, chain.Table) {
				owned = append(owned, normalizeOwnedObject("chain", object))
			}
			continue
		}
		for _, kind := range []string{"set", "map", "counter"} {
			rawOwnedObject, ok := object[kind]
			if !ok {
				continue
			}
			var location struct {
				Family string `json:"family"`
				Table  string `json:"table"`
			}
			if err := json.Unmarshal(rawOwnedObject, &location); err != nil {
				return NFTSnapshot{}, fmt.Errorf("decode nftables %s location: %w", kind, err)
			}
			if isOwnedTable(location.Family, location.Table) {
				owned = append(owned, normalizeOwnedObject(kind, object))
			}
			break
		}
		if rawRule, ok := object["rule"]; ok {
			var location struct {
				Family string `json:"family"`
				Table  string `json:"table"`
				Chain  string `json:"chain"`
			}
			if err := json.Unmarshal(rawRule, &location); err != nil {
				return NFTSnapshot{}, fmt.Errorf("decode nftables rule location: %w", err)
			}
			if !isOwnedTable(location.Family, location.Table) {
				continue
			}
			rule, err := decodeRule(rawRule)
			if err != nil {
				return NFTSnapshot{}, fmt.Errorf("decode nftables rule: %w", err)
			}
			owned = append(owned, normalizeOwnedObject("rule", object))
			if rule.Comment == "" {
				continue
			}
			kind, id, ok := parseSemanticCounterComment(rule.Comment)
			if !ok {
				continue
			}
			if _, exists := seenCounterIDs[id]; exists {
				return NFTSnapshot{}, fmt.Errorf("duplicate semantic counter id %q", id)
			}
			packets, bytes, found, err := ruleCounter(rule.Expr)
			if err != nil {
				return NFTSnapshot{}, fmt.Errorf("decode counter %q: %w", rule.Comment, err)
			}
			if !found {
				return NFTSnapshot{}, fmt.Errorf("semantic counter %q has no counter expression", rule.Comment)
			}
			seenCounterIDs[id] = struct{}{}
			counters = append(counters, Counter{Rule: rule.Comment, ID: id, Kind: kind, Family: rule.Family, Table: rule.Table, Chain: rule.Chain, Packets: packets, Bytes: bytes})
			if len(counters) > MaxNFTCounters {
				return NFTSnapshot{}, fmt.Errorf("owned counter count exceeds %d", MaxNFTCounters)
			}
		}
	}

	sort.Slice(counters, func(i, j int) bool { return counters[i].Rule < counters[j].Rule })
	sort.Slice(owned, func(i, j int) bool {
		if owned[i].Kind != owned[j].Kind {
			return owned[i].Kind < owned[j].Kind
		}
		return string(owned[i].Data) < string(owned[j].Data)
	})
	fingerprintInput := make([]byte, 0)
	for _, object := range owned {
		fingerprintInput = append(fingerprintInput, []byte(object.Kind+"\x00")...)
		fingerprintInput = append(fingerprintInput, object.Data...)
		fingerprintInput = append(fingerprintInput, '\n')
	}
	hash := sha256.Sum256(fingerprintInput)
	return NFTSnapshot{Counters: counters, Fingerprint: hex.EncodeToString(hash[:]), OwnedObjectCount: len(owned)}, nil
}

type normalizedObject struct {
	Kind string
	Data []byte
}

type nftTable struct {
	Family string `json:"family"`
	Name   string `json:"name"`
}

type nftChain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
}

type nftRule struct {
	Family  string          `json:"family"`
	Table   string          `json:"table"`
	Chain   string          `json:"chain"`
	Comment string          `json:"comment"`
	Expr    json.RawMessage `json:"expr"`
}

func decodeObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		if err == nil {
			err = fmt.Errorf("object is not a JSON object")
		}
		return nil, err
	}
	return object, nil
}

func decodeTable(raw json.RawMessage) (nftTable, error) {
	var table nftTable
	if err := json.Unmarshal(raw, &table); err != nil {
		return nftTable{}, err
	}
	if table.Family == "" || table.Name == "" {
		return nftTable{}, fmt.Errorf("table identity is incomplete")
	}
	return table, nil
}

func decodeChain(raw json.RawMessage) (nftChain, error) {
	var chain nftChain
	if err := json.Unmarshal(raw, &chain); err != nil {
		return nftChain{}, err
	}
	if chain.Family == "" || chain.Table == "" || chain.Name == "" {
		return nftChain{}, fmt.Errorf("chain identity is incomplete")
	}
	return chain, nil
}

func decodeRule(raw json.RawMessage) (nftRule, error) {
	var rule nftRule
	if err := json.Unmarshal(raw, &rule); err != nil {
		return nftRule{}, err
	}
	if rule.Family == "" || rule.Table == "" || rule.Chain == "" {
		return nftRule{}, fmt.Errorf("rule identity is incomplete")
	}
	if len(rule.Comment) > MaxNFTComment {
		return nftRule{}, fmt.Errorf("rule comment exceeds %d bytes", MaxNFTComment)
	}
	return rule, nil
}

func ruleCounter(rawExpressions json.RawMessage) (uint64, uint64, bool, error) {
	if len(rawExpressions) == 0 || string(rawExpressions) == "null" {
		return 0, 0, false, nil
	}
	var expressions []json.RawMessage
	if err := json.Unmarshal(rawExpressions, &expressions); err != nil {
		return 0, 0, false, fmt.Errorf("expressions: %w", err)
	}
	var packets, bytes uint64
	found := false
	for index, rawExpression := range expressions {
		expression, err := decodeObject(rawExpression)
		if err != nil {
			return 0, 0, false, fmt.Errorf("expression %d: %w", index, err)
		}
		rawCounter, ok := expression["counter"]
		if !ok {
			continue
		}
		if found {
			return 0, 0, false, fmt.Errorf("multiple counter expressions")
		}
		counter, err := decodeObject(rawCounter)
		if err != nil {
			return 0, 0, false, fmt.Errorf("counter expression: %w", err)
		}
		packets, err = decodeUint64(counter["packets"])
		if err != nil {
			return 0, 0, false, fmt.Errorf("packets: %w", err)
		}
		bytes, err = decodeUint64(counter["bytes"])
		if err != nil {
			return 0, 0, false, fmt.Errorf("bytes: %w", err)
		}
		found = true
	}
	return packets, bytes, found, nil
}

func decodeUint64(raw json.RawMessage) (uint64, error) {
	if len(raw) == 0 {
		return 0, fmt.Errorf("value is missing")
	}
	value, err := strconv.ParseUint(string(raw), 10, 64)
	if err != nil || strings.ContainsAny(string(raw), ".eE+-") {
		return 0, fmt.Errorf("value is not an unsigned integer")
	}
	return value, nil
}

func parseSemanticCounterComment(comment string) (string, string, bool) {
	parts := strings.Split(comment, ":")
	if len(parts) != 3 || parts[0] != "boetticher" || (parts[1] != "allow" && parts[1] != "deny" && parts[1] != "drop") || parts[2] == "" || len(parts[2]) > MaxNFTComment {
		return "", "", false
	}
	if _, err := SemanticCounterComment(parts[1], parts[2]); err != nil {
		return "", "", false
	}
	return parts[1], parts[2], true
}

func normalizeOwnedObject(kind string, object map[string]json.RawMessage) normalizedObject {
	value := make(map[string]any, len(object))
	for key, raw := range object {
		if key == "handle" || key == "index" || key == "position" {
			continue
		}
		var decoded any
		if json.Unmarshal(raw, &decoded) != nil {
			decoded = string(raw)
		}
		value[key] = normalizeValue(decoded, "")
	}
	data, _ := json.Marshal(value)
	return normalizedObject{Kind: kind, Data: data}
}

func normalizeValue(value any, parent string) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, child := range typed {
			if key == "handle" || key == "index" || key == "position" {
				continue
			}
			if parent == "counter" && (key == "packets" || key == "bytes") {
				continue
			}
			result[key] = normalizeValue(child, key)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, child := range typed {
			result[index] = normalizeValue(child, parent)
		}
		if parent == "elem" || parent == "elements" {
			sort.Slice(result, func(i, j int) bool {
				left, _ := json.Marshal(result[i])
				right, _ := json.Marshal(result[j])
				return string(left) < string(right)
			})
		}
		return result
	default:
		return value
	}
}

// ReadBounded reads an nft snapshot from a stream without allowing an
// unbounded pipe or helper output to reach the JSON decoder.
func ReadBounded(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxNFTJSONBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxNFTJSONBytes {
		return nil, fmt.Errorf("nftables JSON exceeds %d bytes", MaxNFTJSONBytes)
	}
	return data, nil
}
