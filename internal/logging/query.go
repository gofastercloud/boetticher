package logging

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"time"
)

const QueryPort = 19533
const AIOpsLogClientIdentity = "aiops-log-read"

func VerifyQueryClient(state tls.ConnectionState) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("journal query requires a leaf client certificate")
	}
	got := state.PeerCertificates[0].Subject.CommonName
	if len(got) != len(AIOpsLogClientIdentity) || subtle.ConstantTimeCompare([]byte(got), []byte(AIOpsLogClientIdentity)) != 1 {
		return errors.New("journal query client identity is not authorized")
	}
	return nil
}

type QueryRequest struct {
	Host         string `json:"host"`
	Unit         string `json:"unit,omitempty"`
	Priority     string `json:"priority,omitempty"`
	SinceMinutes int    `json:"since_minutes"`
	Limit        int    `json:"limit"`
}

type QueryPolicy struct {
	Hosts map[string][]string `json:"hosts"`
}

var queryToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var queryPriorities = map[string]bool{"emerg": true, "alert": true, "crit": true, "err": true, "warning": true, "notice": true, "info": true, "debug": true}

func (p QueryPolicy) Validate(r QueryRequest) error {
	units, ok := p.Hosts[r.Host]
	if !ok || !queryToken.MatchString(r.Host) || r.SinceMinutes < 1 || r.SinceMinutes > 120 || r.Limit < 1 || r.Limit > 200 || (r.Priority != "" && !queryPriorities[r.Priority]) {
		return errors.New("journal query is outside policy")
	}
	if r.Unit != "" {
		allowed := false
		for _, unit := range units {
			if unit == r.Unit {
				allowed = true
				break
			}
		}
		if !allowed || !queryToken.MatchString(r.Unit) {
			return errors.New("journal unit is outside policy")
		}
	}
	return nil
}

func QueryArguments(r QueryRequest) []string {
	args := []string{"--directory=/var/log/journal/remote", "--no-pager", "--output=json", "--since=-" + strconv.Itoa(r.SinceMinutes) + " minutes", "--lines=" + strconv.Itoa(r.Limit), "_HOSTNAME=" + r.Host}
	if r.Unit != "" {
		args = append(args, "_SYSTEMD_UNIT="+r.Unit)
	}
	if r.Priority != "" {
		args = append(args, "--priority="+r.Priority)
	}
	return args
}

type CommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

type QueryServer struct {
	Policy QueryPolicy
	Runner CommandRunner
}

func (s QueryServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"healthy"}`)
	})
	mux.HandleFunc("POST /v1/query", s.query)
	return mux
}
func (s QueryServer) query(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "application/json required", http.StatusUnsupportedMediaType)
		return
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	decoder.DisallowUnknownFields()
	var request QueryRequest
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "invalid query", http.StatusBadRequest)
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		http.Error(w, "invalid query", http.StatusBadRequest)
		return
	}
	if err := s.Policy.Validate(request); err != nil {
		http.Error(w, "query rejected", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	output, err := s.Runner.Run(ctx, "/usr/bin/journalctl", QueryArguments(request)...)
	if err != nil {
		http.Error(w, "journal query failed", http.StatusBadGateway)
		return
	}
	if len(output) > 32*1024 {
		http.Error(w, "journal response exceeded limit", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(output)
}

func LoadQueryPolicy(path string) (QueryPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return QueryPolicy{}, err
	}
	var policy QueryPolicy
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return QueryPolicy{}, fmt.Errorf("decode journal query policy: %w", err)
	}
	if len(policy.Hosts) == 0 {
		return QueryPolicy{}, errors.New("journal query policy has no managed hosts")
	}
	return policy, nil
}
