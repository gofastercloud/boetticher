package proxmox

import (
	"context"
	"net/http"
	"testing"
)

func TestNodeStorageReadsCapacityAndRegistrationState(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method != http.MethodGet || r.URL.Path != "/api2/json/nodes/lab-proxmox-01/storage" {
			t.Fatalf("unexpected storage request: %s %s", r.Method, r.URL.Path)
		}
		return response([]byte(`{"data":[{"storage":"boetticher-thin","type":"lvmthin","active":1,"total":1000,"used":400,"avail":600},{"storage":"boetticher-backups","type":"dir","active":1,"total":2000,"used":500,"avail":1500}]}`))
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	statuses, err := client.NodeStorage(context.Background(), "lab-proxmox-01")
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 2 || statuses[0].Active != 1 || statuses[1].Avail != 1500 {
		t.Fatalf("unexpected storage status: %#v", statuses)
	}
}
