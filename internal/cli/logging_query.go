package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/observability"
)

const (
	maxLoggingQueryValueBytes    = 128
	maxLoggingQueryResponseBytes = 1 << 20
	maxLoggingQueryOutputBytes   = 64 << 10
	maxLoggingQueryFieldRunes    = 2048
)

var loggingQueryLevels = map[string]struct{}{
	"trace": {}, "debug": {}, "info": {}, "notice": {}, "warn": {}, "warning": {},
	"error": {}, "err": {}, "critical": {}, "crit": {}, "alert": {},
	"emergency": {}, "emerg": {}, "fatal": {},
}

var loggingQueryTransport = func(config controllerhost.LabConfig) (observability.Runner, error) {
	return observabilityTransport(config)
}

type loggingQueryOptions struct {
	host, unit, level string
	since             time.Duration
	limit             int
}

type loggingQueryEntry struct {
	timestamp string
	severity  string
	host      string
	unit      string
	message   string
}

func runLoggingQuery(args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("module logging query", flag.ContinueOnError)
	fs.SetOutput(errOut)
	host := fs.String("host", "", "restrict results to a host")
	unit := fs.String("unit", "", "restrict results to a systemd unit")
	level := fs.String("level", "", "restrict results to a log level")
	since := fs.String("since", "1h", "look back by a bounded duration (maximum 168h)")
	limit := fs.Int("limit", 100, "maximum number of log lines (1-500)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("module logging query accepts flags only; positional arguments are not supported")
	}

	options, err := validateLoggingQueryOptions(*host, *unit, *level, *since, *limit)
	if err != nil {
		return err
	}

	config, err := loadLabConfig()
	if err != nil {
		return err
	}
	transport, err := loggingQueryTransport(config)
	if err != nil {
		return err
	}
	binding, ok := observability.BindingFor("observability")
	if !ok {
		return errors.New("observability logging runtime binding is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := observability.HostClient{Transport: transport}
	if _, err := client.GuestConfig(ctx, binding); err != nil {
		return fmt.Errorf("logging query refused: shared observability guest ownership check failed: %w", err)
	}

	requestURL, err := loggingQueryURL(options)
	if err != nil {
		return err
	}
	// The URL and all user values are shell-quoted as one guest argument. The
	// only Host command is the fixed pct exec for the owned observability LXC.
	script := "set -eu; exec curl --fail --silent --show-error --max-time 15 --header 'Accept: application/x-ndjson' " + shellQuote(requestURL)
	result, err := transport.Run(ctx, fmt.Sprintf("pct exec %d -- sh -c %s", binding.VMID, shellQuote(script)))
	if err != nil {
		return fmt.Errorf("logging query request failed: %w", err)
	}
	if len(result.Stdout) > maxLoggingQueryResponseBytes {
		return fmt.Errorf("logging query response exceeds %d bytes", maxLoggingQueryResponseBytes)
	}
	entries, err := parseLoggingQueryJSONL(result.Stdout)
	if err != nil {
		return fmt.Errorf("logging query returned invalid JSONL: %w", err)
	}
	renderLoggingQuery(out, entries)
	return nil
}

func validateLoggingQueryOptions(host, unit, level, sinceValue string, limit int) (loggingQueryOptions, error) {
	for name, value := range map[string]string{"--host": host, "--unit": unit, "--level": level} {
		if err := validateLoggingQueryValue(name, value); err != nil {
			return loggingQueryOptions{}, err
		}
	}
	since, err := time.ParseDuration(sinceValue)
	if err != nil || since <= 0 || since > 168*time.Hour {
		return loggingQueryOptions{}, errors.New("--since must be a positive duration no longer than 168h")
	}
	if limit < 1 || limit > 500 {
		return loggingQueryOptions{}, errors.New("--limit must be between 1 and 500")
	}
	if level != "" {
		level = strings.ToLower(level)
		if _, ok := loggingQueryLevels[level]; !ok {
			return loggingQueryOptions{}, errors.New("--level must be a recognised log level")
		}
	}
	return loggingQueryOptions{host: host, unit: unit, level: level, since: since, limit: limit}, nil
}

func validateLoggingQueryValue(name, value string) error {
	if len(value) > maxLoggingQueryValueBytes {
		return fmt.Errorf("%s exceeds %d bytes", name, maxLoggingQueryValueBytes)
	}
	if strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("%s contains forbidden control characters", name)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s contains forbidden control characters", name)
		}
	}
	return nil
}

func loggingQueryURL(options loggingQueryOptions) (string, error) {
	filters := make([]string, 0, 3)
	for _, item := range []struct{ name, value string }{{"host", options.host}, {"unit", options.unit}, {"level", options.level}} {
		if item.value != "" {
			// LogsQL values are fixed literals; strconv.Quote escapes quotes and
			// backslashes before url.Values performs URL encoding.
			filters = append(filters, item.name+"="+strconv.Quote(item.value))
		}
	}
	query := "_time:" + loggingQueryDuration(options.since)
	if len(filters) > 0 {
		query = "{" + strings.Join(filters, ", ") + "} " + query
	}
	values := url.Values{}
	values.Set("query", query)
	values.Set("limit", strconv.Itoa(options.limit))
	return "http://127.0.0.1:9428/select/logsql/query?" + values.Encode(), nil
}

func loggingQueryDuration(value time.Duration) string {
	if value%time.Hour == 0 {
		return strconv.FormatInt(int64(value/time.Hour), 10) + "h"
	}
	if value%time.Minute == 0 {
		return strconv.FormatInt(int64(value/time.Minute), 10) + "m"
	}
	return strconv.FormatInt(int64(value/time.Second), 10) + "s"
}

func parseLoggingQueryJSONL(data []byte) ([]loggingQueryEntry, error) {
	if len(data) > maxLoggingQueryResponseBytes {
		return nil, fmt.Errorf("response exceeds %d bytes", maxLoggingQueryResponseBytes)
	}
	entries := make([]loggingQueryEntry, 0)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxLoggingQueryResponseBytes)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var fields map[string]any
		decoder := json.NewDecoder(bytes.NewReader(line))
		if err := decoder.Decode(&fields); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			if err == nil {
				return nil, fmt.Errorf("line %d contains multiple JSON values", lineNumber)
			}
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}
		if fields == nil {
			return nil, fmt.Errorf("line %d is not a JSON object", lineNumber)
		}
		entries = append(entries, loggingQueryEntry{
			timestamp: loggingQueryField(fields, "_time", "timestamp", "time", "@timestamp"),
			severity:  loggingQueryField(fields, "level", "severity", "_level", "PRIORITY", "priority"),
			host:      loggingQueryField(fields, "host", "hostname", "_HOSTNAME"),
			unit:      loggingQueryField(fields, "unit", "_SYSTEMD_UNIT"),
			message:   loggingQueryField(fields, "_msg", "message", "msg"),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan response: %w", err)
	}
	return entries, nil
}

func loggingQueryField(fields map[string]any, names ...string) string {
	for _, name := range names {
		value, ok := fields[name]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			return sanitizeLoggingQueryField(typed)
		case json.Number:
			return sanitizeLoggingQueryField(typed.String())
		default:
			return sanitizeLoggingQueryField(fmt.Sprint(typed))
		}
	}
	return "-"
}

func sanitizeLoggingQueryField(value string) string {
	value = strings.Map(func(r rune) rune {
		if r == '\x1b' || r == '\x7f' || r < 0x20 {
			return ' '
		}
		return r
	}, value)
	runes := []rune(value)
	if len(runes) > maxLoggingQueryFieldRunes {
		return string(runes[:maxLoggingQueryFieldRunes-3]) + "..."
	}
	return value
}

func renderLoggingQuery(out io.Writer, entries []loggingQueryEntry) {
	var rendered bytes.Buffer
	for _, entry := range entries {
		line := entry.timestamp + "\t" + entry.severity + "\t" + entry.host + "\t" + entry.unit + "\t" + entry.message + "\n"
		if rendered.Len()+len(line) > maxLoggingQueryOutputBytes {
			const marker = "[output truncated]\n"
			if rendered.Len()+len(marker) <= maxLoggingQueryOutputBytes {
				rendered.WriteString(marker)
			}
			break
		}
		rendered.WriteString(line)
	}
	_, _ = out.Write(rendered.Bytes())
}
