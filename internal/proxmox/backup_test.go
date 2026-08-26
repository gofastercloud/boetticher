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

func TestApplyBackupJobRefusesConflictingUnownedJob(t *testing.T) {
	putCalled := false
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method == http.MethodGet && r.URL.Path == "/api2/json/cluster/backup" {
			return response([]byte(`{"data":[{"id":"boetticher-platform","notes-template":"Operator backup job"}]}`))
		}
		if r.Method == http.MethodPut {
			putCalled = true
		}
		return response([]byte(`{"data":null}`))
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	err := client.ApplyBackupJob(context.Background(), "lab-proxmox-01", BackupJob{
		JobName: "boetticher-platform", ModelRevision: "sha256:abc", StorageTarget: "local",
		Schedule: "daily", VMIDList: "100,110", Retention: "keep-last=7",
	})
	if err == nil {
		t.Fatal("expected conflicting unowned backup job to be rejected")
	}
	if putCalled {
		t.Fatal("convergence updated an unowned backup job")
	}
}

func TestApplyBackupJobUpdatesOwnedJob(t *testing.T) {
	putCalled := false
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method == http.MethodGet && r.URL.Path == "/api2/json/cluster/backup" {
			return response([]byte(`{"data":[{"id":"boetticher-platform","notes-template":"Managed by boetticher; model revision sha256:old"}]}`))
		}
		if r.Method == http.MethodPut && r.URL.Path == "/api2/json/cluster/backup/boetticher-platform" {
			putCalled = true
			return response([]byte(`{"data":null}`))
		}
		return response([]byte(`{"data":null}`))
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := client.ApplyBackupJob(context.Background(), "lab-proxmox-01", BackupJob{
		JobName: "boetticher-platform", ModelRevision: "sha256:new", StorageTarget: "local",
		Schedule: "daily", VMIDList: "100,110", Retention: "keep-last=7",
	}); err != nil {
		t.Fatal(err)
	}
	if !putCalled {
		t.Fatal("owned backup job was not updated")
	}
}
