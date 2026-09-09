package main

import (
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

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
	homepageDir := flag.String("homepage-config", "", "optional Homepage config directory to refresh from lab.yml")
	refresh := flag.String("homepage-refresh-url", "", "optional local Homepage refresh URL")
	interval := flag.Duration("refresh-interval", 15*time.Second, "lab.yml refresh interval")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/lab", func(w http.ResponseWriter, r *http.Request) { serveLab(w, *path) })
	mux.Handle("/", http.FileServer(http.FS(assets)))
	if *homepageDir != "" {
		go watchHomepage(*path, *homepageDir, *refresh, *interval)
	}
	log.Printf("lab viewer listening on %s (lab=%s)", *addr, *path)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func watchHomepage(labPath, configDir, refreshURL string, interval time.Duration) {
	if interval < time.Second {
		interval = time.Second
	}
	var last time.Time
	for {
		if info, err := os.Stat(labPath); err == nil && info.ModTime().After(last) {
			if err := syncHomepage(labPath, configDir); err != nil {
				log.Printf("homepage config refresh failed: %v", err)
			} else {
				last = info.ModTime()
				if refreshURL != "" {
					request, _ := http.NewRequest(http.MethodPost, refreshURL, nil)
					response, err := http.DefaultClient.Do(request)
					if err == nil && response.Body != nil {
						response.Body.Close()
					}
				}
			}
		}
		time.Sleep(interval)
	}
}

func syncHomepage(labPath, configDir string) error {
	b, err := os.ReadFile(labPath)
	if err != nil {
		return err
	}
	var raw map[string]any
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return err
	}
	normalizeMap(raw)
	links := publications(raw)
	sort.SliceStable(links, func(i, j int) bool {
		if links[i].Group == links[j].Group {
			return links[i].Name < links[j].Name
		}
		return links[i].Group < links[j].Group
	})
	grouped := map[string][]map[string]map[string]string{}
	for _, link := range links {
		grouped[link.Group] = append(grouped[link.Group], map[string]map[string]string{link.Name: {
			"href": link.URL, "description": link.Description, "icon": homepageIcon(link.Icon),
		}})
	}
	groups := make([]string, 0, len(grouped))
	for group := range grouped {
		groups = append(groups, group)
	}
	sort.Strings(groups)
	services := make([]map[string][]map[string]map[string]string, 0, len(groups))
	for _, group := range groups {
		services = append(services, map[string][]map[string]map[string]string{group: grouped[group]})
	}
	settings := map[string]any{
		"title": "Boetticher Lab", "description": "Private control room for the lab", "theme": "dark",
		"color": "green", "headerStyle": "clean", "statusStyle": "dot", "iconStyle": "theme",
		"background": map[string]any{"image": "/images/boetticher-cover.jpg", "blur": "sm", "saturate": 60, "opacity": 35},
	}
	if err := os.MkdirAll(filepath.Join(configDir, "images"), 0750); err != nil {
		return err
	}
	cover, err := assets.ReadFile("static/boetticher-cover.jpg")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(configDir, "images", "boetticher-cover.jpg"), cover, 0640); err != nil {
		return err
	}
	if err := writeYAMLAtomic(filepath.Join(configDir, "services.yaml"), services); err != nil {
		return err
	}
	if err := writeYAMLAtomic(filepath.Join(configDir, "settings.yaml"), settings); err != nil {
		return err
	}
	return writeYAMLAtomic(filepath.Join(configDir, "bookmarks.yaml"), map[string]any{})
}

func homepageIcon(icon string) string {
	icons := map[string]string{"◌": "gatus.png", "◈": "grafana.png", "▦": "proxmox.png", "▶": "jellyfin.png", "✦": "jellyseerr.png", "⌁": "mdi-firewall"}
	if value, ok := icons[icon]; ok {
		return value
	}
	return "mdi-open-in-new"
}

func writeYAMLAtomic(path string, value any) error {
	b, err := yaml.Marshal(value)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".labviewer-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0640); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(b); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, path)
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
	default:
		return value
	}
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
			out = append(out, endpoint{name, desc, url, group, icon, source})
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
