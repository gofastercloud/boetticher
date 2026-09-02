package streamdeck

import (
	"context"
	"encoding/json"
	"image"
	"image/color"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestConfigRejectsUnknownFieldsAndUnsafePulseURL(t *testing.T) {
	_, err := LoadConfig(strings.NewReader(`{"pulse_url":"https://monitor.example?x=1"}`))
	if err == nil {
		t.Fatal("unsafe Pulse URL was accepted")
	}
	_, err = LoadConfig(strings.NewReader(`{"pulse_url":"https://monitor.example","client_certificate":"cert","client_key":"key","ca_certificate":"ca","unexpected":true}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown configuration field error = %v", err)
	}
}

func TestPulseFetchIsBoundedAndPaginates(t *testing.T) {
	var requests []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests = append(requests, request.URL.String())
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/health":
			_, _ = writer.Write([]byte(`{"status":"healthy"}`))
		case "/api/state/summary":
			_, _ = writer.Write([]byte(`{}`))
		case "/api/resources":
			if request.URL.Query().Get("page") == "1" {
				items := make([]map[string]any, pageSize)
				for i := range items {
					items[i] = map[string]any{"name": "node-a", "type": "agent", "platformType": "proxmox", "status": "up", "metrics": map[string]any{"cpu": 10, "memory": 20}}
				}
				_ = json.NewEncoder(writer).Encode(map[string]any{"resources": items})
				return
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"resources": []map[string]any{{"name": "node-b", "type": "agent", "platformType": "proxmox", "status": "down", "metrics": map[string]any{"cpu": 101}}}})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client, err := newPulseClient(server.URL, "read-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	state, err := client.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Resources) != 101 || state.Resources[0].CPU == nil || *state.Resources[0].CPU != 10 || state.Resources[100].CPU != nil {
		t.Fatalf("unexpected Pulse state: %#v", state)
	}
	if len(requests) != 4 || !strings.Contains(requests[2], "page=1") || !strings.Contains(requests[3], "page=2") {
		t.Fatalf("unexpected Pulse requests: %#v", requests)
	}
}

func TestProxmoxHostsAcceptsProxmoxAgentsOnly(t *testing.T) {
	hosts := ProxmoxHosts([]Resource{
		{Name: "standalone-agent", Kind: "agent", PlatformType: "linux"},
		{Name: "pve-node", Kind: "agent", PlatformType: "proxmox"},
		{Name: "legacy-node", Kind: "node"},
	})
	if len(hosts) != 2 || hosts[0].Name != "legacy-node" || hosts[1].Name != "pve-node" {
		t.Fatalf("unexpected Proxmox hosts: %#v", hosts)
	}
}

func TestPulseRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(append([]byte{'{'}, make([]byte, maxPulseResponse)...))
	}))
	defer server.Close()
	client, err := newPulseClient(server.URL, "token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.json(context.Background(), "/api/health"); err == nil || !strings.Contains(err.Error(), "4 MiB") {
		t.Fatalf("oversized response error = %v", err)
	}
}

func TestRenderShowsHostsAndStaleState(t *testing.T) {
	deck := &fakeDeck{buttons: 15, size: 72, images: map[int]image.Image{}}
	value := 12.4
	memory := 33.6
	state := &State{
		Resources: []Resource{
			{Name: "node-b", Kind: "node", Status: "up"},
			{Name: "guest", Kind: "lxc", Status: "up"},
			{Name: "node-a", Kind: "node", Status: "up", CPU: &value, Memory: &memory},
		},
		ReceivedAt: time.Now().UTC(),
		Stale:      "*net.OpError",
	}
	if err := Render(context.Background(), deck, state); err != nil {
		t.Fatal(err)
	}
	if len(deck.images) != 15 {
		t.Fatalf("rendered %d buttons", len(deck.images))
	}
	if deck.colors[0] != red || deck.colors[1] != red {
		t.Fatalf("stale hosts were not marked red: %#v", deck.colors)
	}
}

func TestRenderWaitAndNoHostsAreFailSafe(t *testing.T) {
	for _, state := range []*State{nil, {Resources: []Resource{}}} {
		deck := &fakeDeck{buttons: 2, size: 72, images: map[int]image.Image{}}
		if err := Render(context.Background(), deck, state); err != nil {
			t.Fatal(err)
		}
		if len(deck.images) != 2 {
			t.Fatalf("rendered %d buttons", len(deck.images))
		}
	}
}

type fakeDeck struct {
	buttons int
	size    int
	images  map[int]image.Image
	colors  map[int]color.Color
	pending image.Image
}

func (d *fakeDeck) ButtonCount() int                           { return d.buttons }
func (d *fakeDeck) ImageSize() int                             { return d.size }
func (d *fakeDeck) SetBrightness(context.Context, uint8) error { return nil }
func (d *fakeDeck) ProcessImage(value image.Image) ([]byte, error) {
	d.pending = value
	return []byte{1}, nil
}
func (d *fakeDeck) SetButton(_ context.Context, index int, _ []byte) error {
	if d.colors == nil {
		d.colors = map[int]color.Color{}
	}
	d.images[index] = d.pending
	d.colors[index] = colorAtCorner(d.pending)
	return nil
}
func (d *fakeDeck) Close(context.Context) error { return nil }

func colorAtCorner(value image.Image) color.Color {
	if value == nil {
		return nil
	}
	return value.At(0, 0)
}
