package aiops

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const MaxWebhookBytes = 32 * 1024

type Server struct {
	Store         *Store
	WebhookSecret []byte
	Now           func() time.Time
	OnResolved    func(string)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("POST /v1/pulse/events", s.admit)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "healthy"})
}

func (s *Server) admit(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "application/json required", http.StatusUnsupportedMediaType)
		return
	}
	want := "Bearer " + string(s.WebhookSecret)
	got := r.Header.Get("Authorization")
	if len(got) != len(want) || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var alert Alert
	if err := strictDecode(http.MaxBytesReader(w, r.Body, MaxWebhookBytes), &alert); err != nil {
		http.Error(w, "invalid alert", http.StatusBadRequest)
		return
	}
	incident, duplicate, err := s.Store.Admit(r.Context(), alert, s.now())
	if err != nil {
		http.Error(w, "incident was not persisted", http.StatusServiceUnavailable)
		return
	}
	if alert.Status == "resolved" {
		if err := s.Store.Resolve(r.Context(), incident.ID, "pulse_resolution", s.now()); err != nil {
			http.Error(w, "resolution was not persisted", http.StatusServiceUnavailable)
			return
		}
		if s.OnResolved != nil {
			s.OnResolved(incident.ID)
		}
		incident.State = StateResolved
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"incident_id": incident.ID, "state": incident.State, "duplicate": duplicate})
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func strictDecode(r io.Reader, value any) error {
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON is forbidden")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func ReadCredential(directory, name string) ([]byte, error) {
	if directory == "" || !safeToken(name) {
		return nil, errors.New("credential directory and safe name are required")
	}
	data, err := os.ReadFile(directory + "/" + name)
	if err != nil {
		return nil, err
	}
	data = []byte(strings.TrimSpace(string(data)))
	if len(data) < 32 || len(data) > 4096 {
		return nil, errors.New("credential has an invalid bounded length")
	}
	return data, nil
}
