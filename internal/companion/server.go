package companion

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

//go:embed web/*
var assets embed.FS

func Handler(s *State, control bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		if !control && r.Host != HTTPAddress {
			http.Error(w, "invalid host", http.StatusForbidden)
			return
		}
		if r.URL.Path == "/api/status" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(s.Snapshot())
			return
		}
		if r.URL.Path == "/api/rendered" && !control && r.Method == http.MethodPost {
			if r.Header.Get("Origin") != "http://"+HTTPAddress {
				http.Error(w, "invalid origin", http.StatusForbidden)
				return
			}
			_ = s.Heartbeat("display")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if control && r.Method == http.MethodPost && (r.URL.Path == "/action" || r.URL.Path == "/heartbeat") {
			var in struct {
				Action string `json:"action"`
				Target string `json:"target"`
			}
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&in); err != nil {
				http.Error(w, "invalid request", 400)
				return
			}
			var tail any
			if decoder.Decode(&tail) != io.EOF {
				http.Error(w, "trailing request data", 400)
				return
			}
			var err error
			if r.URL.Path == "/heartbeat" {
				err = s.Heartbeat(in.Action)
			} else {
				err = s.Action(in.Action, in.Target)
			}
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if !control && r.Method == http.MethodGet {
			if r.URL.Path == "/favicon.ico" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			name := ""
			contentType := ""
			switch r.URL.Path {
			case "/":
				name = "index.html"
				contentType = "text/html; charset=utf-8"
			case "/app.js":
				name = "app.js"
				contentType = "text/javascript"
			case "/style.css":
				name = "style.css"
				contentType = "text/css"
			}
			if name != "" {
				body, err := assets.ReadFile("web/" + name)
				if err != nil {
					http.Error(w, "asset unavailable", 500)
					return
				}
				w.Header().Set("Content-Type", contentType)
				_, _ = w.Write(body)
				return
			}
		}
		http.Error(w, "not found", http.StatusNotFound)
	})
}

func Serve(ctx context.Context, s *State) error {
	local, err := net.Listen("tcp", HTTPAddress)
	if err != nil {
		return err
	}
	defer local.Close()
	// RuntimeDirectory is private to the service and recreated on stop.
	if info, err := os.Lstat(SocketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("control path is not a socket")
		}
		if err := os.Remove(SocketPath); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	unixListener, err := net.Listen("unix", SocketPath)
	if err != nil {
		return err
	}
	defer unixListener.Close()
	if err := os.Chmod(SocketPath, 0660); err != nil {
		return err
	}
	servers := []*http.Server{{Handler: Handler(s, false)}, {Handler: Handler(s, true)}}
	errorsCh := make(chan error, 2)
	for i, listener := range []net.Listener{local, unixListener} {
		server := servers[i]
		server.ReadHeaderTimeout = 2 * time.Second
		server.ReadTimeout = 3 * time.Second
		server.WriteTimeout = 3 * time.Second
		server.IdleTimeout = 10 * time.Second
		go func() { errorsCh <- server.Serve(listener) }()
	}
	select {
	case <-ctx.Done():
		err = nil
	case err = <-errorsCh:
	}
	for _, server := range servers {
		_ = server.Close()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func LocalClient() *http.Client {
	return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", SocketPath)
	}}}
}
func ReadSnapshot(ctx context.Context, client *http.Client) (Snapshot, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://companion/api/status", nil)
	if err != nil {
		return Snapshot{}, err
	}
	response, err := client.Do(req)
	if err != nil {
		return Snapshot{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return Snapshot{}, fmt.Errorf("status HTTP %d", response.StatusCode)
	}
	var snapshot Snapshot
	err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&snapshot)
	if err == nil && (snapshot.Version != 1 || len(snapshot.Items) != 8 || !fresh(snapshot.UpdatedAt, time.Now())) {
		err = errors.New("invalid or stale companion snapshot")
	}
	return snapshot, err
}

func Check(snapshot Snapshot) error {
	if snapshot.Version != 1 || len(snapshot.Items) != 8 || !fresh(snapshot.UpdatedAt, time.Now()) {
		return errors.New("invalid or stale Companion status")
	}
	for i, item := range snapshot.Items {
		if item.ID != itemIDs[i] {
			return errors.New("invalid Companion component identity")
		}
		if item.Status != Healthy && item.Status != Disabled {
			return fmt.Errorf("%s: %s", item.Label, item.Reason)
		}
	}
	if snapshot.Blinkt && time.Since(snapshot.BlinktAt) > 10*time.Second {
		return errors.New("Blinkt renderer is not updating")
	}
	for _, module := range snapshot.Modules {
		if module.Status != Healthy && module.Status != Disabled {
			return fmt.Errorf("%s: %s", module.Label, module.Reason)
		}
	}
	return nil
}
