package model

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParseSiteConfig is the strict 0.5 site.yml decoder. The version probe gives
// operators a concise recreate-site message before strict decoding reports
// fields that are not part of the v3 configuration.
func ParseSiteConfig(data []byte) (SiteConfig, error) {
	var probe struct {
		APIVersion string `yaml:"api_version"`
	}
	probeDecoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := probeDecoder.Decode(&probe); err != nil {
		return SiteConfig{}, fmt.Errorf("decode site.yml: %w", err)
	}
	if probe.APIVersion == "" {
		return SiteConfig{}, fmt.Errorf("site.yml: api_version is required and must be boetticher/v3")
	}
	if probe.APIVersion != APIVersion {
		return SiteConfig{}, fmt.Errorf("site schema %q is not supported by boetticher %s; recreate the site with boetticher init", probe.APIVersion, ReleaseVersion)
	}
	if err := validateModuleConfigShape(data); err != nil {
		return SiteConfig{}, err
	}
	var config SiteConfig
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		return SiteConfig{}, fmt.Errorf("decode site.yml: %w", err)
	}
	for name := range config.Modules.Map() {
		if name != "dns" && name != "monitoring" && name != "firewall" && name != "logging" && name != "tailnet-router" && name != "bifrost" && name != "printer" && name != "aiops" && name != "gatus" && name != "airvpn" && name != "arr" {
			return SiteConfig{}, fmt.Errorf("site.yml: modules.%s is not a registered first-party module", name)
		}
	}
	return config, nil
}

func validateModuleConfigShape(data []byte) error {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("decode site.yml: %w", err)
	}
	if len(document.Content) == 0 {
		return nil
	}
	root := document.Content[0]
	modules := mappingValue(root, "modules")
	if companion := mappingValue(root, "companion"); companion != nil {
		if companion.Kind != yaml.MappingNode {
			return errors.New("site.yml: companion expected a mapping")
		}
		for index := 0; index+1 < len(companion.Content); index += 2 {
			name := companion.Content[index].Value
			value := companion.Content[index+1]
			if name == "ethernet_mac" || name == "streamdeck_serial" {
				if value.Tag != "!!str" {
					return fmt.Errorf("site.yml: companion.%s: expected a string", name)
				}
				continue
			}
			if name == "enabled" {
				if value.Tag != "!!bool" && value.Tag != "!!null" {
					return errors.New("site.yml: companion.enabled: expected a boolean")
				}
				continue
			}
			if name != "display" && name != "streamdeck" && name != "pulse_agent" && name != "blinkt" {
				return fmt.Errorf("site.yml: companion.%s: unknown field", name)
			}
			if value.Kind != yaml.MappingNode {
				return fmt.Errorf("site.yml: companion.%s expected a mapping", name)
			}
			for fieldIndex := 0; fieldIndex+1 < len(value.Content); fieldIndex += 2 {
				if value.Content[fieldIndex].Value != "enabled" {
					return fmt.Errorf("site.yml: companion.%s.%s: unknown field", name, value.Content[fieldIndex].Value)
				}
				fieldValue := value.Content[fieldIndex+1]
				if fieldValue.Tag != "!!bool" && fieldValue.Tag != "!!null" {
					return fmt.Errorf("site.yml: companion.%s.enabled: expected a boolean", name)
				}
			}
		}
	}
	if modules == nil {
		return nil
	}
	if modules.Kind != yaml.MappingNode {
		return errors.New("site.yml: modules expected a mapping")
	}
	for index := 0; index+1 < len(modules.Content); index += 2 {
		name := modules.Content[index].Value
		value := modules.Content[index+1]
		allowed := map[string]bool{}
		switch name {
		case "dns":
		case "monitoring", "firewall", "printer":
			allowed["enabled"] = true
			if name == "printer" {
				allowed["network"] = true
			}
		case "logging":
			allowed["enabled"] = true
		case "tailnet-router":
			allowed["enabled"] = true
		case "bifrost":
			allowed["enabled"] = true
			allowed["network"] = true
			allowed["upstreams"] = true
			allowed["models"] = true
		case "aiops", "gatus", "arr":
			allowed["enabled"] = true
			allowed["network"] = true
			if name == "aiops" {
				allowed["model_alias"] = true
			}
		case "airvpn":
			allowed["enabled"] = true
			allowed["servers"] = true
		default:
			return fmt.Errorf("site.yml: modules.%s: unknown first-party module", name)
		}
		if value.Kind != yaml.MappingNode {
			return fmt.Errorf("site.yml: modules.%s expected a mapping", name)
		}
		for fieldIndex := 0; fieldIndex+1 < len(value.Content); fieldIndex += 2 {
			field := value.Content[fieldIndex].Value
			fieldValue := value.Content[fieldIndex+1]
			if !allowed[field] {
				if name == "dns" && field == "enabled" {
					return fmt.Errorf("site.yml: modules.%s.enabled: mandatory module cannot be disabled", name)
				}
				return fmt.Errorf("site.yml: modules.%s.%s: unknown field", name, field)
			}
			if field == "enabled" && fieldValue.Tag != "!!bool" && fieldValue.Tag != "!!null" {
				return fmt.Errorf("site.yml: modules.%s.enabled: expected a boolean", name)
			}
			if field == "network" && fieldValue.Tag != "!!str" {
				return fmt.Errorf("site.yml: modules.%s.network: expected a string", name)
			}
			if name == "airvpn" && field == "servers" && fieldValue.Tag != "!!str" {
				return fmt.Errorf("site.yml: modules.airvpn.servers: expected a string")
			}
			if name == "bifrost" && (field == "upstreams" || field == "models") && fieldValue.Kind != yaml.SequenceNode {
				return fmt.Errorf("site.yml: modules.bifrost.%s: expected a list", field)
			}
			if name == "aiops" && field == "model_alias" && fieldValue.Tag != "!!str" {
				return fmt.Errorf("site.yml: modules.aiops.model_alias: expected a string")
			}
		}
	}
	return nil
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		if node.Content[index].Value == key {
			return node.Content[index+1]
		}
	}
	return nil
}

func RenderSiteConfig(config SiteConfig) ([]byte, error) {
	data, err := yaml.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("encode site.yml: %w", err)
	}
	return data, nil
}

// ParseDocument exposes the same constrained YAML reader used by site.yml for
// small generated documents such as the encrypted secret envelope.
func ParseDocument(data []byte) (any, error) {
	var value any
	if err := json.Unmarshal(data, &value); err == nil {
		return value, nil
	}
	return parseYAML(data)
}

type yamlLine struct {
	indent int
	text   string
	line   int
}

func parseYAML(data []byte) (any, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var lines []yamlLine
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := strings.TrimRight(scanner.Text(), " \t")
		if strings.TrimSpace(raw) == "" || strings.HasPrefix(strings.TrimSpace(raw), "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		if strings.Contains(raw[:indent], "\t") {
			return nil, fmt.Errorf("line %d: tabs are not supported for indentation", lineNo)
		}
		lines = append(lines, yamlLine{indent: indent, text: strings.TrimSpace(raw), line: lineNo})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("site.yml is empty")
	}
	value, next, err := parseBlock(lines, 0, lines[0].indent)
	if err != nil {
		return nil, err
	}
	if next != len(lines) {
		return nil, fmt.Errorf("line %d: unexpected content", lines[next].line)
	}
	return value, nil
}

func parseBlock(lines []yamlLine, index, indent int) (any, int, error) {
	if index >= len(lines) || lines[index].indent != indent {
		return nil, index, fmt.Errorf("expected indentation at line %d", lines[index].line)
	}
	if strings.HasPrefix(lines[index].text, "- ") || lines[index].text == "-" {
		var result []any
		for index < len(lines) && lines[index].indent == indent && (strings.HasPrefix(lines[index].text, "- ") || lines[index].text == "-") {
			content := strings.TrimSpace(strings.TrimPrefix(lines[index].text, "-"))
			line := lines[index].line
			index++
			if content == "" {
				if index >= len(lines) || lines[index].indent <= indent {
					return nil, index, fmt.Errorf("line %d: list item requires a value", line)
				}
				child, next, err := parseBlock(lines, index, lines[index].indent)
				if err != nil {
					return nil, index, err
				}
				result = append(result, child)
				index = next
				continue
			}
			if key, value, ok := splitPair(content); ok {
				item := map[string]any{key: value}
				if index < len(lines) && lines[index].indent > indent {
					child, next, err := parseBlock(lines, index, lines[index].indent)
					if err != nil {
						return nil, index, err
					}
					childMap, ok := child.(map[string]any)
					if !ok {
						return nil, index, fmt.Errorf("line %d: list mapping continuation must be a mapping", line)
					}
					for k, v := range childMap {
						if _, exists := item[k]; exists {
							return nil, index, fmt.Errorf("line %d: duplicate key %q", line, k)
						}
						item[k] = v
					}
					index = next
				}
				result = append(result, item)
				continue
			}
			result = append(result, parseScalar(content))
		}
		return result, index, nil
	}

	result := map[string]any{}
	for index < len(lines) && lines[index].indent == indent && !strings.HasPrefix(lines[index].text, "- ") {
		line := lines[index]
		key, value, ok := splitPair(line.text)
		if !ok || key == "" {
			return nil, index, fmt.Errorf("line %d: expected key: value", line.line)
		}
		if _, exists := result[key]; exists {
			return nil, index, fmt.Errorf("line %d: duplicate key %q", line.line, key)
		}
		index++
		if value == "|" || strings.HasPrefix(value, "|-") || strings.HasPrefix(value, "|+") {
			var block strings.Builder
			for index < len(lines) && lines[index].indent > indent {
				block.WriteString(lines[index].text)
				block.WriteByte('\n')
				index++
			}
			result[key] = block.String()
			continue
		}
		if value != "" {
			result[key] = parseScalar(value)
			continue
		}
		if index >= len(lines) || lines[index].indent <= indent {
			result[key] = nil
			continue
		}
		child, next, err := parseBlock(lines, index, lines[index].indent)
		if err != nil {
			return nil, index, err
		}
		result[key] = child
		index = next
	}
	return result, index, nil
}

func splitPair(text string) (string, string, bool) {
	quote := byte(0)
	for i := 0; i < len(text); i++ {
		c := text[i]
		if quote != 0 {
			if c == quote && (i == 0 || text[i-1] != '\\') {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
		} else if c == ':' {
			return strings.TrimSpace(text[:i]), strings.TrimSpace(stripComment(text[i+1:])), true
		}
	}
	return "", "", false
}

func stripComment(value string) string {
	quote := byte(0)
	for i := 0; i < len(value); i++ {
		if quote != 0 {
			if value[i] == quote && (i == 0 || value[i-1] != '\\') {
				quote = 0
			}
			continue
		}
		if value[i] == '\'' || value[i] == '"' {
			quote = value[i]
		} else if value[i] == '#' && (i == 0 || value[i-1] == ' ') {
			return strings.TrimSpace(value[:i])
		}
	}
	return strings.TrimSpace(value)
}

func parseScalar(value string) any {
	if value == "[]" {
		return []any{}
	}
	if value == "{}" {
		return map[string]any{}
	}
	if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
		if value[0] == '"' {
			if unquoted, err := strconv.Unquote(value); err == nil {
				return unquoted
			}
		}
		return value[1 : len(value)-1]
	}
	switch value {
	case "true":
		return true
	case "false":
		return false
	case "null", "~":
		return nil
	}
	if i, err := strconv.Atoi(value); err == nil {
		return i
	}
	if f, err := strconv.ParseFloat(value, 64); err == nil {
		return f
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		var array []any
		for _, item := range strings.Split(strings.TrimSpace(value[1:len(value)-1]), ",") {
			if strings.TrimSpace(item) != "" {
				array = append(array, parseScalar(strings.TrimSpace(item)))
			}
		}
		return array
	}
	return value
}
