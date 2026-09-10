package incidents

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"io"
	"net"
	"net/http"
	"strings"
)

// Handler is the narrow HTTP boundary for alert intake and private incident
// reports.  The caller supplies authentication and, optionally, a read-only
// investigator.  It intentionally has no shell, SSH, or credential-file
// access.
type Handler struct {
	Store        *Store
	WebhookToken string
	Authorize    func(*http.Request) bool
	Investigator Investigator
}

const maxWebhookBytes = 64 * 1024

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Store == nil {
		http.Error(w, "incident store unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/health" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
		return
	}
	if strings.HasPrefix(r.URL.Path, "/webhooks/") {
		h.handleWebhook(w, r)
		return
	}
	if h.Authorize == nil || !h.Authorize(r) {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/incidents":
		h.handleList(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/incidents/"):
		h.handleShow(w, r, strings.TrimPrefix(r.URL.Path, "/api/incidents/"))
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/investigate"):
		h.handleInvestigate(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/incidents":
		h.handleHTML(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h Handler) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || (h.WebhookToken == "" || !bearerMatches(r.Header.Get("Authorization"), h.WebhookToken)) && !loopbackRemote(r.RemoteAddr) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxWebhookBytes+1))
	if err != nil || len(body) > maxWebhookBytes {
		http.Error(w, "alert payload is too large", http.StatusRequestEntityTooLarge)
		return
	}
	var alert Alert
	if err := json.Unmarshal(body, &alert); err != nil || alert.Title == "" {
		var provider map[string]any
		if json.Unmarshal(body, &provider) != nil {
			http.Error(w, "invalid alert payload", http.StatusBadRequest)
			return
		}
		alert = Alert{Source: strings.TrimPrefix(r.URL.Path, "/webhooks/"), Labels: map[string]string{}}
		alert.Title, _ = provider["title"].(string)
		if alert.Title == "" {
			alert.Title, _ = provider["name"].(string)
		}
		alert.Body, _ = provider["body"].(string)
		if alert.Body == "" {
			alert.Body, _ = provider["description"].(string)
		}
		alert.Group, _ = provider["group"].(string)
		alert.Fingerprint, _ = provider["fingerprint"].(string)
		if source, ok := provider["source"].(string); ok && source != "" {
			alert.Source = source
		}
		if status, ok := provider["status"].(string); ok && status != "" {
			alert.Labels["status"] = status
		}
		if alert.Title == "" {
			http.Error(w, "alert title is required", http.StatusBadRequest)
			return
		}
	}
	if alert.Source == "" {
		alert.Source = strings.TrimPrefix(r.URL.Path, "/webhooks/")
	}
	incident, duplicate, err := h.Store.Intake(r.Context(), alert)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{"id": incident.ID, "duplicate": duplicate, "state": incident.State})
}

func loopbackRemote(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (h Handler) handleList(w http.ResponseWriter, r *http.Request) {
	items, err := h.Store.List(r.Context())
	if err != nil {
		http.Error(w, "incident list unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, items)
}

func (h Handler) handleShow(w http.ResponseWriter, r *http.Request, id string) {
	if !safeID(id) {
		http.Error(w, "invalid incident id", http.StatusBadRequest)
		return
	}
	item, ok, err := h.Store.Get(r.Context(), id, true)
	if err != nil {
		http.Error(w, "incident lookup failed", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, item)
}

func (h Handler) handleInvestigate(w http.ResponseWriter, r *http.Request) {
	if h.Investigator == nil || (!csrfOK(r) && !bearerMatches(r.Header.Get("Authorization"), h.WebhookToken)) {
		http.Error(w, "investigation unavailable", http.StatusForbidden)
		return
	}
	path := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/incidents/"), "/investigate")
	if !safeID(path) {
		http.Error(w, "invalid incident id", http.StatusBadRequest)
		return
	}
	item, err := h.Store.Investigate(r.Context(), path, h.Investigator)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, item)
}

func (h Handler) handleHTML(w http.ResponseWriter, r *http.Request) {
	items, err := h.Store.List(r.Context())
	if err != nil {
		http.Error(w, "incident list unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	csrf := make([]byte, 18)
	if _, err := rand.Read(csrf); err == nil {
		http.SetCookie(w, &http.Cookie{Name: "boetticher_csrf", Value: hex.EncodeToString(csrf), Path: "/", HttpOnly: false, SameSite: http.SameSiteStrictMode})
	}
	_ = incidentPage.Execute(w, map[string]any{"Incidents": items})
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func bearerMatches(header, token string) bool {
	prefix := "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	got := []byte(strings.TrimSpace(strings.TrimPrefix(header, prefix)))
	want := []byte(token)
	return len(got) == len(want) && subtle.ConstantTimeCompare(got, want) == 1
}

func csrfOK(r *http.Request) bool {
	cookie, err := r.Cookie("boetticher_csrf")
	if err != nil || cookie.Value == "" {
		return false
	}
	got, want := []byte(r.Header.Get("X-CSRF-Token")), []byte(cookie.Value)
	return len(got) == len(want) && subtle.ConstantTimeCompare(got, want) == 1
}

func safeID(value string) bool {
	if value == "" || len(value) > maxAlertID {
		return false
	}
	for _, char := range value {
		if !(char == '-' || char == '_' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9') {
			return false
		}
	}
	return true
}

var incidentPage = template.Must(template.New("incidents").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>Boetticher incidents</title></head>
<body><h1>Boetticher incidents</h1><ul>{{range .Incidents}}<li><a href="/api/incidents/{{.ID}}">{{.Title}}</a> — {{.State}} ({{.Source}})</li>{{else}}<li>No incidents.</li>{{end}}</ul></body></html>`))
