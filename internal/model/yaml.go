package model

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// The site contract intentionally uses a small, deterministic YAML subset.
// JSON is also accepted because JSON is valid YAML and is useful for tooling.
func ParseSite(data []byte) (Site, error) {
	var site Site
	if err := json.Unmarshal(data, &site); err == nil {
		return site, nil
	}
	value, err := parseYAML(data)
	if err != nil {
		return Site{}, err
	}
	normalized, err := json.Marshal(value)
	if err != nil {
		return Site{}, err
	}
	if err := json.Unmarshal(normalized, &site); err != nil {
		return Site{}, fmt.Errorf("decode site.yml: %w", err)
	}
	return site, nil
}

// ParseSiteConfig is the strict v0.3 site.yml decoder. The small version
// probe gives operators the useful recreate-site message before strict
// decoding can report removed v0.2 fields such as components.
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
	if probe.APIVersion != "boetticher/v3" {
		return SiteConfig{}, fmt.Errorf("site schema %q is not supported by boetticher v0.3; recreate the site with boetticher init", probe.APIVersion)
	}
	var config SiteConfig
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		return SiteConfig{}, fmt.Errorf("decode site.yml: %w", err)
	}
	return config, nil
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

func RenderSite(s Site) ([]byte, error) {
	data, err := json.MarshalIndent(s.Normalize(), "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
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
