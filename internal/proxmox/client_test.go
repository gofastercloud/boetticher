package proxmox

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) *http.Response

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request), nil
}

func TestClientUsesTokenAndDecodesEnvelope(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Header.Get("Authorization") != "PVEAPIToken=labadmin@pve!boetticher=secret" {
			t.Errorf("unexpected authorization header: %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/api2/json/version" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		data, _ := json.Marshal(map[string]any{"data": map[string]string{"version": "8.4"}})
		return response(data)
	})
	client, err := NewClient(Config{BaseURL: "http://127.0.0.1:8006", User: "labadmin@pve", TokenID: "boetticher", TokenSecret: "secret"})
	if err == nil {
		t.Fatal("insecure HTTP base URL was accepted")
	}
	client = &Client{BaseURL: "https://127.0.0.1:8006/api2/json", Token: "PVEAPIToken=labadmin@pve!boetticher=secret", HTTP: &http.Client{Transport: transport}}
	version, err := client.Version(context.Background())
	if err != nil || version != "8.4" {
		t.Fatalf("Version() = %q, %v", version, err)
	}
}

func TestQEMUAgentNetworkInterfacesUsesGuestAgentEndpoint(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method != http.MethodGet || r.URL.Path != "/api2/json/nodes/lab-proxmox-01/qemu/190/agent/network-get-interfaces" {
			t.Fatalf("unexpected guest-agent request: %s %s", r.Method, r.URL.Path)
		}
		return response([]byte(`{"data":[{"name":"eth0","hardware-address":"02:00:00:00:00:01","ip-addresses":[{"ip-address":"127.0.0.1","ip-address-type":"ipv4"},{"ip-address":"192.0.2.15","ip-address-type":"ipv4"}]}]}`))
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	interfaces, err := client.QEMUAgentNetworkInterfaces(context.Background(), "lab-proxmox-01", 190)
	if err != nil || len(interfaces) != 1 || interfaces[0].IPAddresses[1].IPAddress != "192.0.2.15" {
		t.Fatalf("QEMUAgentNetworkInterfaces() = %#v, %v", interfaces, err)
	}
}

func TestCreateTokenUsesFormEncoding(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("unexpected request: %s %s", r.Method, r.Header.Get("Content-Type"))
		}
		if err := r.ParseForm(); err != nil || r.Form.Get("privsep") != "1" {
			t.Errorf("unexpected form: %v", r.Form)
		}
		data, _ := json.Marshal(map[string]any{"data": map[string]string{"value": "token-secret"}})
		return response(data)
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	secret, err := client.CreateToken(context.Background(), "labadmin@pve", "boetticher")
	if err != nil || secret != "token-secret" {
		t.Fatalf("CreateToken() = %q, %v", secret, err)
	}
}

func TestUploadStorageFileUsesMultipartArtifactContract(t *testing.T) {
	path := t.TempDir() + "/artifact.tar.zst"
	if err := os.WriteFile(path, []byte("artifact bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method != http.MethodPost || r.URL.Path != "/api2/json/nodes/lab-proxmox-01/storage/local/upload" {
			t.Fatalf("unexpected upload request: %s %s", r.Method, r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data;") {
			t.Fatalf("upload was not multipart: %q", r.Header.Get("Content-Type"))
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Fatal(err)
		}
		if got := r.FormValue("content"); got != "vztmpl" {
			t.Fatalf("content = %q, want vztmpl", got)
		}
		file, header, err := r.FormFile("filename")
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if header.Filename != "boetticher-logging-1.0.0-amd64.tar.zst" {
			t.Fatalf("filename = %q", header.Filename)
		}
		data, err := io.ReadAll(file)
		if err != nil || string(data) != "artifact bytes" {
			t.Fatalf("uploaded bytes = %q, err=%v", data, err)
		}
		return response([]byte(`{"data":null}`))
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := client.UploadStorageFile(context.Background(), "lab-proxmox-01", "local", "vztmpl", path, "boetticher-logging-1.0.0-amd64.tar.zst"); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureDirectoryStorageCreatesBackupStorage(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method == http.MethodGet && r.URL.Path == "/api2/json/cluster/storage" {
			return response([]byte(`{"data":[]}`))
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api2/json/cluster/storage" {
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse storage form: %v", err)
			}
			if got := r.Form.Get("storage"); got != "boetticher-backups" {
				t.Errorf("storage = %q, want boetticher-backups", got)
			}
			if got := r.Form.Get("path"); got != "/srv/boetticher/backups" {
				t.Errorf("path = %q, want /srv/boetticher/backups", got)
			}
			if got := r.Form.Get("content"); got != "backup" {
				t.Errorf("content = %q, want backup", got)
			}
			return response([]byte(`{"data":null}`))
		}
		t.Errorf("unexpected storage request: %s %s", r.Method, r.URL.Path)
		return response([]byte(`{"data":null}`))
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := client.EnsureDirectoryStorage(context.Background(), "boetticher-backups", "/srv/boetticher/backups"); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureDirectoryStorageRejectsConflictingDefinition(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		data, _ := json.Marshal(map[string]any{"data": []map[string]string{{
			"storage": "boetticher-backups", "type": "dir", "path": "/wrong/path", "content": "backup",
		}}})
		return response(data)
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := client.EnsureDirectoryStorage(context.Background(), "boetticher-backups", "/srv/boetticher/backups"); err == nil {
		t.Fatal("conflicting storage definition was accepted")
	}
}

func TestEnsureDirectoryStorageContentAddsOnlyRequiredTypes(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method == http.MethodGet && r.URL.Path == "/api2/json/cluster/storage" {
			return response([]byte(`{"data":[{"storage":"local","type":"dir","path":"/var/lib/vz","content":"backup,iso,vztmpl"}]}`))
		}
		if r.Method == http.MethodPut && r.URL.Path == "/api2/json/cluster/storage/local" {
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if got := r.Form.Get("content"); got != "backup,images,iso,rootdir,vztmpl" {
				t.Fatalf("content = %q", got)
			}
			return response([]byte(`{"data":null}`))
		}
		t.Fatalf("unexpected storage request: %s %s", r.Method, r.URL.Path)
		return nil
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := client.EnsureDirectoryStorageContent(context.Background(), "local", "/var/lib/vz", []string{"backup", "images", "rootdir"}); err != nil {
		t.Fatal(err)
	}
}

func TestDownloadURLUsesPinnedChecksumWithoutShellArguments(t *testing.T) {
	checksum := strings.Repeat("a", 128)
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method != http.MethodPost || r.URL.Path != "/api2/json/nodes/lab-proxmox-01/storage/local/download-url" {
			t.Fatalf("unexpected image download request: %s %s", r.Method, r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		for key, want := range map[string]string{
			"content": "iso", "filename": "debian-13.qcow2", "url": "https://images.example/debian-13.qcow2", "checksum": checksum, "checksum-algorithm": "sha512",
		} {
			if got := r.Form.Get(key); got != want {
				t.Errorf("%s = %q, want %q", key, got, want)
			}
		}
		return response([]byte(`{"data":"UPID:pve:download"}`))
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	upid, err := client.DownloadURL(context.Background(), "lab-proxmox-01", "local", "debian-13.qcow2", "https://images.example/debian-13.qcow2", checksum)
	if err != nil || upid != "UPID:pve:download" {
		t.Fatalf("DownloadURL() = %q, %v", upid, err)
	}
}

func TestDownloadURLRejectsUnpinnedOrUnsafeInputs(t *testing.T) {
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: roundTripFunc(func(r *http.Request) *http.Response { return response([]byte(`{"data":"unexpected"}`)) })}}
	if _, err := client.DownloadURL(context.Background(), "node", "local", "../image.qcow2", "https://images.example/image.qcow2", strings.Repeat("a", 128)); err == nil {
		t.Fatal("unsafe image filename was accepted")
	}
	if _, err := client.DownloadURL(context.Background(), "node", "local", "image.qcow2", "https://images.example/image.qcow2", "not-a-sha512"); err == nil {
		t.Fatal("unverified image checksum was accepted")
	}
}

func TestImportDiskUsesThePinnedStoragePlan(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method != http.MethodPost || r.URL.Path != "/api2/json/nodes/node/qemu/100/importdisk" {
			t.Fatalf("unexpected import request: %s %s", r.Method, r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if got := url.Values(r.Form).Get("source"); got != "local:iso/debian-13.qcow2" {
			t.Errorf("source = %q", got)
		}
		if got := r.Form.Get("storage"); got != "boetticher-thin" {
			t.Errorf("storage = %q", got)
		}
		if got := r.Form.Get("format"); got != "qcow2" {
			t.Errorf("format = %q", got)
		}
		return response([]byte(`{"data":"UPID:pve:import"}`))
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	upid, err := client.ImportDisk(context.Background(), "node", 100, "local:iso/debian-13.qcow2", "boetticher-thin", "qcow2")
	if err != nil || upid != "UPID:pve:import" {
		t.Fatalf("ImportDisk() = %q, %v", upid, err)
	}
}

func response(data []byte) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(data)))}
}
