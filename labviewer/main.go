package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"gopkg.in/yaml.v3"
)

//go:embed static/*
var assets embed.FS

type endpoint struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	URL         string `json:"url"`
	Group       string `json:"group"`
	Icon        string `json:"icon,omitempty"`
	Source      string `json:"source,omitempty"`
}

type payload struct {
	UpdatedAt time.Time         `json:"updated_at"`
	Path      string            `json:"path"`
	Summary   map[string]string `json:"summary"`
	Links     []endpoint        `json:"links"`
	Config    any               `json:"config"`
}

var secretWords = []string{"secret", "token", "password", "credential", "private_key", "age_recipient", "fingerprint", "api_key", "key_file"}

func main() {
	defaultPath := os.Getenv("BOETTICHER_LAB_YML")
	if defaultPath == "" {
		defaultPath = "/etc/boetticher/lab.yml"
	}
	path := flag.String("lab", defaultPath, "path to the live lab.yml")
	addr := flag.String("listen", ":8090", "listen address")
	snapshotDir := flag.String("snapshot-dir", "/var/lib/boetticher/labviewer/snapshot", "directory for the published lab snapshot")
	factsPath := flag.String("facts", "", "optional bounded observed-facts JSON path")
	docsRoot := flag.String("docs-root", "/opt/boetticher/docs", "documentation root published beneath /lab/docs/")
	snapshotInterval := flag.Duration("snapshot-interval", 5*time.Minute, "lab snapshot refresh interval")
	syncVMID := flag.Int("sync-vmid", 0, "optional Monitoring VMID receiving the published snapshot")
	syncPath := flag.String("sync-path", "/var/lib/boetticher/labviewer/snapshot/snapshot.json", "path for the synced snapshot on the Monitoring guest")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/lab", func(w http.ResponseWriter, r *http.Request) { serveLab(w, *path) })
	mux.HandleFunc("/lab", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/lab/", http.StatusMovedPermanently)
	})
	mux.Handle("/lab/", labHandler(*snapshotDir, *docsRoot))
	mux.Handle("/", http.FileServer(http.FS(assets)))
	go watchSnapshot(*path, *factsPath, *docsRoot, *snapshotDir, *snapshotInterval, *syncVMID, *syncPath)
	log.Printf("lab viewer listening on %s (lab=%s)", *addr, *path)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func labHandler(snapshotDir, docsRoot string) http.Handler {
	static, err := fs.Sub(assets, "static")
	if err != nil {
		panic(err)
	}
	mux := http.NewServeMux()
	// Serving the static subtree makes /lab/ resolve to index.html instead of
	// exposing the embedded asset directory.
	mux.Handle("/lab/", http.StripPrefix("/lab/", http.FileServer(http.FS(static))))
	mux.HandleFunc("/lab/snapshot.json", func(w http.ResponseWriter, r *http.Request) {
		serveSnapshot(w, filepath.Join(snapshotDir, "snapshot.json"))
	})
	mux.Handle("/lab/docs/", http.StripPrefix("/lab/docs/", http.FileServer(http.Dir(docsRoot))))
	return mux
}

func watchSnapshot(labPath, factsPath, docsRoot, snapshotDir string, interval time.Duration, syncVMID int, syncPath string) {
	if interval < time.Minute {
		interval = time.Minute
	}
	refresh := func() {
		snapshot, err := buildSnapshot(labPath, factsPath, docsRoot, time.Now().UTC())
		if err != nil {
			log.Printf("lab snapshot refresh failed: %v", err)
			return
		}
		if err := writeSnapshotAtomic(snapshotDir, snapshot); err != nil {
			log.Printf("lab snapshot publish failed: %v", err)
			return
		}
		if syncVMID > 0 {
			if err := syncSnapshot(context.Background(), snapshot, syncVMID, syncPath); err != nil {
				log.Printf("lab snapshot sync failed: %v", err)
			}
		}
	}
	refresh()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		refresh()
	}
}

func syncSnapshot(ctx context.Context, snapshot labSnapshot, vmid int, path string) error {
	config, err := controllerhost.LoadConfig()
	if err != nil {
		return fmt.Errorf("load Controller configuration: %w", err)
	}
	transport, err := controllerhost.TransportFor(config)
	if err != nil {
		return fmt.Errorf("configure Host transport: %w", err)
	}
	transport.Timeout = 30 * time.Second
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	payloadCommand := fmt.Sprintf("set -eu; install -d -m 0750 %s; chown root:holmes %s; tmp=$(mktemp %s.XXXXXX); trap 'rm -f -- \"$tmp\"' EXIT HUP INT TERM; cat >\"$tmp\"; chmod 0640 \"$tmp\"; chown root:holmes \"$tmp\"; mv -f \"$tmp\" %s", shellQuote(filepath.Dir(path)), shellQuote(filepath.Dir(path)), shellQuote(path), shellQuote(path))
	command := fmt.Sprintf("pct exec %d -- sh -c %s", vmid, shellQuote(payloadCommand))
	if _, err := transport.RunWithStdin(ctx, command, bytes.NewReader(append(data, '\n'))); err != nil {
		return fmt.Errorf("sync snapshot to VMID %d: %w", vmid, err)
	}
	return nil
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

func serveSnapshot(w http.ResponseWriter, path string) {
	w.Header().Set("Content-Type", "application/json")
	snapshot, err := readSnapshot(path)
	if err != nil {
		http.Error(w, "lab snapshot unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, snapshot)
}

func serveLab(w http.ResponseWriter, path string) {
	w.Header().Set("Content-Type", "application/json")
	b, err := os.ReadFile(path)
	if err != nil {
		writeJSON(w, map[string]any{"error": fmt.Sprintf("cannot read lab configuration: %v", err)})
		return
	}
	var raw map[string]any
	if err := yaml.Unmarshal(b, &raw); err != nil {
		writeJSON(w, map[string]any{"error": fmt.Sprintf("cannot parse lab configuration: %v", err)})
		return
	}
	normalizeMap(raw)
	links := publications(raw)
	sort.SliceStable(links, func(i, j int) bool {
		if links[i].Group == links[j].Group {
			return links[i].Name < links[j].Name
		}
		return links[i].Group < links[j].Group
	})
	writeJSON(w, payload{UpdatedAt: time.Now().UTC(), Path: path, Summary: summary(raw), Links: links, Config: redact(raw)})
}

func writeJSON(w http.ResponseWriter, value any) { _ = json.NewEncoder(w).Encode(value) }

func normalizeMap(value any) {
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			normalizeMap(item)
			if m, ok := item.(map[any]any); ok {
				v[key] = convertMap(m)
			}
		}
	case []any:
		for _, item := range v {
			normalizeMap(item)
		}
	}
}
func convertMap(in map[any]any) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		out[fmt.Sprint(k)] = v
	}
	normalizeMap(out)
	return out
}

func redact(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := map[string]any{}
		for key, item := range v {
			if sensitive(key) {
				out[key] = "••••••"
			} else {
				out[key] = redact(item)
			}
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = redact(item)
		}
		return out
	case string:
		return sanitizeURL(v)
	default:
		return value
	}
}

func sanitizeURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User == nil {
		return raw
	}
	parsed.User = nil
	return parsed.String()
}
func sensitive(key string) bool {
	k := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	for _, word := range secretWords {
		if strings.Contains(k, word) {
			return true
		}
	}
	return false
}

func summary(raw map[string]any) map[string]string {
	modules, _ := raw["modules"].(map[string]any)
	enabled := 0
	for _, item := range modules {
		if m, ok := item.(map[string]any); ok {
			if yes, ok := m["enabled"].(bool); !ok || yes {
				enabled++
			}
		}
	}
	network, _ := raw["network"].(map[string]any)
	return map[string]string{"api": stringValue(raw["api_version"], "boetticher/v3"), "domain": stringValue(network["domain"], "lab.home.arpa"), "modules": fmt.Sprintf("%d configured", len(modules)), "active": fmt.Sprintf("%d active", enabled)}
}
func stringValue(value any, fallback string) string {
	if s, ok := value.(string); ok && s != "" {
		return s
	}
	return fallback
}

func publications(raw map[string]any) []endpoint {
	var out []endpoint
	add := func(name, desc, url, group, icon, source string) {
		if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
			out = append(out, endpoint{name, desc, sanitizeURL(url), group, icon, source})
		}
	}
	if pubs, ok := raw["control_surfaces"].([]any); ok {
		for _, item := range pubs {
			if m, ok := item.(map[string]any); ok {
				add(stringValue(m["name"], "Control surface"), stringValue(m["description"], ""), stringValue(m["url"], ""), stringValue(m["group"], "Lab"), stringValue(m["icon"], "↗"), "lab.yml")
			}
		}
	}
	if gateway, ok := raw["gateway"].(map[string]any); ok {
		if pubs, ok := gateway["publish"].([]any); ok {
			for _, item := range pubs {
				if m, ok := item.(map[string]any); ok {
					add(stringValue(m["service"], "Firewall"), "Gateway control surface", stringValue(m["url"], ""), "Network", "⌁", "gateway.publish")
				}
			}
		}
	}
	network, _ := raw["network"].(map[string]any)
	domain := stringValue(network["domain"], "lab.home.arpa")
	add("Gatus", "Service health and synthetic checks", "https://gatus."+domain, "Observe", "◌", "derived")
	add("Grafana", "Dashboards and observability", "https://grafana."+domain, "Observe", "◈", "derived")
	add("Proxmox", "Virtualisation host", "https://pve."+domain, "Operate", "▦", "derived")
	if mods, ok := raw["modules"].(map[string]any); ok {
		if media, ok := mods["media"].(map[string]any); ok {
			if media["enabled"] != false {
				appDomain := stringValue(media["application_domain"], "")
				if appDomain != "" {
					aliases, _ := media["aliases"].(map[string]any)
					for service, host := range aliases {
						add(titleName(service), "Media application", "https://"+stringValue(host, service)+"."+appDomain, "Media", "▶", "modules.media.aliases")
					}
					add("Jellyfin", "Media library", "https://jellyfin."+appDomain, "Media", "▶", "derived")
					add("Jellyseerr", "Requests", "https://jellyseerr."+appDomain, "Media", "✦", "derived")
				}
			}
		}
	}
	return unique(out)
}

func titleName(value string) string {
	if value == "" {
		return value
	}
	return strings.ToUpper(value[:1]) + value[1:]
}
func unique(in []endpoint) []endpoint {
	seen := map[string]bool{}
	out := in[:0]
	for _, item := range in {
		if item.URL == "" || seen[item.URL] {
			continue
		}
		seen[item.URL] = true
		out = append(out, item)
	}
	return out
}
