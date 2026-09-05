package companion

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBrowserCannotControlConsole(t *testing.T) {
	s := NewState(Config{})
	handler := Handler(s, false)
	for _, path := range []string{"/action", "/heartbeat"} {
		r := httptest.NewRequest(http.MethodPost, "http://"+HTTPAddress+path, strings.NewReader(`{"action":"dim"}`))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code < 400 {
			t.Fatal("HTTP action accepted")
		}
	}
	r := httptest.NewRequest(http.MethodGet, "http://attacker.example/api/status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("foreign Host accepted")
	}
}
func TestControlRejectsUnknownAndTrailingData(t *testing.T) {
	handler := Handler(NewState(Config{}), true)
	for _, body := range []string{`{"action":"exec","target":"reboot"}`, `{"action":"home","command":"reboot"}`, `{"action":"home"}{}`} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("POST", "http://companion/action", strings.NewReader(body)))
		if w.Code != 400 {
			t.Fatalf("accepted %s", body)
		}
	}
}
func TestRenderHeartbeatRequiresSameOrigin(t *testing.T) {
	s := NewState(Config{Display: true})
	handler := Handler(s, false)
	r := httptest.NewRequest("POST", "http://"+HTTPAddress+"/api/rendered", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("cross-origin heartbeat accepted")
	}
	r = httptest.NewRequest("POST", "http://"+HTTPAddress+"/api/rendered", nil)
	r.Header.Set("Origin", "http://"+HTTPAddress)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 204 || s.Snapshot().RenderedAt.IsZero() {
		t.Fatal("render not recorded")
	}
}
