package firewalltelemetry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/firewall"
)

const (
	DefaultInterval = 15 * time.Second
	SnapshotMaxAge  = SampleStaleAfter
	MaxHeaderBytes  = 8 << 10
)

type Config struct {
	SnapshotPath   string
	ListenAddress  string
	Port           int
	Interval       time.Duration
	AllowedSources []string
	Now            func() time.Time
}

type Service struct {
	store        *Store
	snapshotPath string
	interval     time.Duration
	allowed      []*net.IPNet
	now          func() time.Time
}

func New(config Config, store *Store) (*Service, error) {
	if store == nil {
		return nil, errors.New("telemetry store is required")
	}
	if config.SnapshotPath == "" || config.ListenAddress == "" || config.Port < 1 || config.Port > 65535 {
		return nil, errors.New("telemetry service network and snapshot configuration is incomplete")
	}
	if config.Interval <= 0 {
		config.Interval = DefaultInterval
	}
	if len(config.AllowedSources) == 0 {
		return nil, errors.New("telemetry service requires an allowed source")
	}
	allowed := make([]*net.IPNet, 0, len(config.AllowedSources))
	for _, value := range config.AllowedSources {
		ip, network, err := net.ParseCIDR(value)
		if err != nil || ip == nil || network == nil || !ip.Equal(network.IP) {
			return nil, fmt.Errorf("invalid telemetry allowed source")
		}
		network.IP = ip
		allowed = append(allowed, network)
	}
	now := config.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Service{store: store, snapshotPath: config.SnapshotPath, interval: config.Interval, allowed: allowed, now: now}, nil
}

func (s *Service) CollectOnce(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	now := s.now()
	info, err := os.Stat(s.snapshotPath)
	if err != nil {
		collectorErr := fmt.Errorf("stat nft snapshot: %w", err)
		_ = s.store.RecordHealthError(now, collectorErr)
		return collectorErr
	}
	if info.ModTime().After(now.Add(time.Minute)) || now.Sub(info.ModTime()) > SnapshotMaxAge {
		collectorErr := errors.New("nft snapshot is stale")
		_ = s.store.RecordHealthError(now, collectorErr)
		return collectorErr
	}
	file, err := os.Open(s.snapshotPath)
	if err != nil {
		collectorErr := fmt.Errorf("open nft snapshot: %w", err)
		_ = s.store.RecordHealthError(now, collectorErr)
		return collectorErr
	}
	data, readErr := firewall.ReadBounded(file)
	closeErr := file.Close()
	if readErr != nil {
		collectorErr := fmt.Errorf("read nft snapshot: %w", readErr)
		_ = s.store.RecordHealthError(now, collectorErr)
		return collectorErr
	}
	if closeErr != nil {
		collectorErr := fmt.Errorf("close nft snapshot: %w", closeErr)
		_ = s.store.RecordHealthError(now, collectorErr)
		return collectorErr
	}
	snapshot, err := firewall.ParseNFTSnapshot(data)
	if err != nil {
		collectorErr := fmt.Errorf("parse nft snapshot: %w", err)
		_ = s.store.RecordHealthError(now, collectorErr)
		return collectorErr
	}
	if err := s.store.RecordSnapshot(now, snapshot); err != nil {
		collectorErr := fmt.Errorf("persist nft snapshot: %w", err)
		_ = s.store.RecordHealthError(now, collectorErr)
		return collectorErr
	}
	return nil
}

func (s *Service) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.CollectOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
		// The health record is the durable error channel; a missing boot-time
		// snapshot must not terminate the API daemon.
	}
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			_ = s.CollectOnce(ctx)
		}
	}
}

func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/api/v1/summary", s.handleSummary)
	mux.HandleFunc("/api/v1/rules", s.handleRules)
	mux.HandleFunc("/api/v1/events", s.handleEvents)
	mux.HandleFunc("/api/v1/rules/", s.handleRule)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !s.authorized(r) {
			writeError(w, http.StatusForbidden, "source is not authorized")
			return
		}
		if strings.Contains(r.URL.Path, "..") {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *Service) authorized(request *http.Request) bool {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, network := range s.allowed {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	if !exactQuery(r.URL, nil) {
		writeError(w, http.StatusBadRequest, "unexpected query")
		return
	}
	health, err := s.store.Health(s.now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "health unavailable")
		return
	}
	status := http.StatusOK
	if health.Status != "healthy" {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]any{"status": health.Status, "collector": health})
}

type Summary struct {
	Collector              CollectorHealth    `json:"collector"`
	LastStructuralChangeAt *time.Time         `json:"last_structural_change_at,omitempty"`
	Windows                []WindowSummary    `json:"windows"`
	SecurityActivity       []SecurityActivity `json:"security_activity"`
}

func (s *Service) handleSummary(w http.ResponseWriter, r *http.Request) {
	if !exactQuery(r.URL, nil) {
		writeError(w, http.StatusBadRequest, "unexpected query")
		return
	}
	now := s.now()
	health, err := s.store.Health(now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "summary unavailable")
		return
	}
	result := Summary{Collector: health, LastStructuralChangeAt: health.LastStructuralChangeAt, Windows: make([]WindowSummary, 0, 3)}
	for _, window := range []struct {
		name     string
		duration time.Duration
	}{
		{name: "5m", duration: 5 * time.Minute},
		{name: "1h", duration: time.Hour},
		{name: "24h", duration: 24 * time.Hour},
	} {
		value, err := s.store.WindowSummary(window.name, now.Add(-window.duration))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "summary unavailable")
			return
		}
		result.Windows = append(result.Windows, value)
	}
	result.SecurityActivity, err = s.store.SecurityActivity(now.Add(-5 * time.Minute))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "summary unavailable")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Service) handleRules(w http.ResponseWriter, r *http.Request) {
	if !exactQuery(r.URL, []string{"limit"}) {
		writeError(w, http.StatusBadRequest, "unexpected query")
		return
	}
	limit, err := parseLimit(r.URL, MaxRuleResults)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid result limit")
		return
	}
	rules, err := s.store.Rules(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "rules unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules, "limit": limit})
}

func (s *Service) handleRule(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/rules/")
	parts := strings.Split(path, "/")
	if len(parts) != 1 && len(parts) != 2 {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	id, err := url.PathUnescape(parts[0])
	if err != nil || !safeRuleID(id) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if len(parts) == 1 {
		if !exactQuery(r.URL, nil) {
			writeError(w, http.StatusBadRequest, "unexpected query")
			return
		}
		rule, err := s.store.Rule(id)
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, "rule not found")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "rule unavailable")
			return
		}
		writeJSON(w, http.StatusOK, rule)
		return
	}
	if len(parts) != 2 || parts[1] != "activity" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	window, err := parseWindow(r.URL.Query().Get("window"))
	if err != nil || !exactQuery(r.URL, []string{"window"}) {
		writeError(w, http.StatusBadRequest, "invalid activity window")
		return
	}
	activity, err := s.store.Activity(id, s.now().Add(-window.duration), MaxActivityResults)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "activity unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rule_id": id, "window": window.name, "samples": activity, "limit": MaxActivityResults})
}

func (s *Service) handleEvents(w http.ResponseWriter, r *http.Request) {
	if !exactQuery(r.URL, []string{"since", "limit"}) {
		writeError(w, http.StatusBadRequest, "unexpected query")
		return
	}
	limit, err := parseLimit(r.URL, MaxEventResults)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid result limit")
		return
	}
	since := s.now().Add(-24 * time.Hour)
	if value := r.URL.Query().Get("since"); value != "" {
		since, err = time.Parse(time.RFC3339Nano, value)
		if err != nil || s.now().Sub(since) > 7*24*time.Hour || since.After(s.now().Add(time.Minute)) {
			writeError(w, http.StatusBadRequest, "invalid event timestamp")
			return
		}
	}
	events, err := s.store.Events(since, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "events unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "limit": limit})
}

type boundedWindow struct {
	name     string
	duration time.Duration
}

func parseWindow(value string) (boundedWindow, error) {
	switch value {
	case "1m":
		return boundedWindow{"1m", time.Minute}, nil
	case "5m":
		return boundedWindow{"5m", 5 * time.Minute}, nil
	case "15m":
		return boundedWindow{"15m", 15 * time.Minute}, nil
	case "1h":
		return boundedWindow{"1h", time.Hour}, nil
	case "6h":
		return boundedWindow{"6h", 6 * time.Hour}, nil
	case "24h":
		return boundedWindow{"24h", 24 * time.Hour}, nil
	case "7d":
		return boundedWindow{"7d", 7 * 24 * time.Hour}, nil
	default:
		return boundedWindow{}, errors.New("window is outside the fixed bounds")
	}
}

func parseLimit(value *url.URL, maximum int) (int, error) {
	text := value.Query().Get("limit")
	if text == "" {
		return maximum, nil
	}
	limit, err := strconv.Atoi(text)
	if err != nil || limit < 1 || limit > maximum {
		return 0, errors.New("limit is outside the fixed bounds")
	}
	return limit, nil
}

func exactQuery(value *url.URL, allowed []string) bool {
	query, err := url.ParseQuery(value.RawQuery)
	if err != nil {
		return false
	}
	for key, values := range query {
		if len(values) != 1 || !contains(allowed, key) {
			return false
		}
	}
	return true
}

func safeRuleID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	if value[0] == '-' {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_') {
			return false
		}
	}
	return true
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encode response failed")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(append(data, '\n'))
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
