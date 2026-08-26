package proxmox

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestApplyBackupJobIncludesRetention(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method == http.MethodGet && r.URL.Path == "/api2/json/cluster/backup" {
			data, _ := json.Marshal(map[string]any{"data": []any{}})
			return response(data)
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api2/json/cluster/backup" {
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse backup form: %v", err)
			}
			if got := r.Form.Get("prune-backups"); got != "keep-last=7" {
				t.Errorf("prune-backups = %q, want keep-last=7", got)
			}
			return response([]byte(`{"data":null}`))
		}
		t.Errorf("unexpected backup request: %s %s", r.Method, r.URL.Path)
		return response([]byte(`{"data":null}`))
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	err := client.ApplyBackupJob(context.Background(), "lab-proxmox-01", BackupJob{
		JobName: "boetticher-platform", ModelRevision: "sha256:abc", StorageTarget: "local",
		Schedule: "daily", VMIDList: "100,110,111,120,130", Retention: "keep-last=7",
	})
	if err != nil {
		t.Fatal(err)
	}
}
