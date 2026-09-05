package companion

import (
	"context"
	"encoding/json"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRemoteDataKeepsUpstreamFreshness(t *testing.T) {
	observed := time.Now().Add(-2 * time.Minute).UTC()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Token") != "read-only" {
			t.Error("missing scoped credential")
		}
		switch r.URL.Path {
		case "/api/health":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "healthy"})
		case "/api/state/summary":
			_ = json.NewEncoder(w).Encode(map[string]any{"lastUpdate": observed})
		case "/api/resources":
			_ = json.NewEncoder(w).Encode(map[string]any{"resources": []map[string]any{{"id": "node:one", "name": "one", "type": "agent", "platformType": "proxmox", "status": "online", "lastSeen": observed}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	state := NewState(Config{})
	collector := Collector{Config: Config{PulseURL: server.URL}, State: state, HTTP: server.Client(), token: "read-only"}
	collector.remote(context.Background())
	snapshot := state.Snapshot()
	if snapshot.Items[4].Status != Failure || snapshot.Items[5].Status != Failure || snapshot.Resources[0].Status != Failure {
		t.Fatal("fresh HTTP hid stale upstream data")
	}
	observed = time.Now().UTC()
	collector.remote(context.Background())
	if state.Snapshot().Items[4].Status != Healthy {
		t.Fatal("fresh node did not recover")
	}
}

func TestDNSCheckCannotUseHostsFile(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		buffer := make([]byte, 4096)
		n, peer, err := listener.ReadFrom(buffer)
		if err != nil {
			done <- err
			return
		}
		var message dnsmessage.Message
		if err = message.Unpack(buffer[:n]); err != nil {
			done <- err
			return
		}
		message.Response = true
		message.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: message.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: [4]byte{198, 51, 100, 1}}}}
		data, err := message.Pack()
		if err == nil {
			_, err = listener.WriteTo(data, peer)
		}
		done <- err
	}()
	if err := verifyDNS(context.Background(), listener.LocalAddr().String(), "localhost", "198.51.100.1"); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPercentSentinelAndUnknownAreNotZero(t *testing.T) {
	for _, raw := range []string{`-1`, `null`, `{}`, `{"unit":"bytes","value":5}`} {
		if value := percent(json.RawMessage(raw)); value != nil {
			t.Fatalf("%s became a percentage", raw)
		}
	}
}
