package proxmox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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

func TestNewClientRejectsNonIPv4APIHosts(t *testing.T) {
	for _, baseURL := range []string{"https://pve.example:8006/api2/json", "https://user@192.0.2.10:8006/api2/json", "https://[::1]:8006/api2/json"} {
		if _, err := NewClient(Config{BaseURL: baseURL}); err == nil {
			t.Fatalf("unsafe Proxmox API base URL was accepted: %s", baseURL)
		}
	}
	if _, err := NewClient(Config{BaseURL: "https://192.0.2.10:8006/api2/json"}); err != nil {
		t.Fatalf("canonical IPv4 Proxmox API base URL was rejected: %v", err)
	}
}

func TestClientIncludesStructuredProxmoxErrors(t *testing.T) {
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: roundTripFunc(func(r *http.Request) *http.Response {
		return apiResponse(http.StatusBadRequest, `{"message":"Parameter verification failed.","errors":{"name":"invalid"},"data":null}`)
	})}}
	err := client.Get(context.Background(), "/nodes/proxmox/qemu/190/config", nil, nil)
	if err == nil || !strings.Contains(err.Error(), `"name":"invalid"`) {
		t.Fatalf("structured Proxmox error was discarded: %v", err)
	}
}

func TestCheckTLSAcceptsUnauthenticatedAPIResponse(t *testing.T) {
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method != http.MethodGet || r.URL.Path != "/api2/json/version" {
			t.Fatalf("unexpected TLS probe request: %s %s", r.Method, r.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusUnauthorized, Status: "401 Unauthorized", Body: io.NopCloser(strings.NewReader("unauthorized")), Header: make(http.Header)}
	})}}
	if err := client.CheckTLS(context.Background()); err != nil {
		t.Fatalf("CheckTLS() = %v", err)
	}
}

func TestNodesUsesAuthoritativeNodesEndpoint(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method != http.MethodGet || r.URL.Path != "/api2/json/nodes" {
			t.Fatalf("unexpected node discovery request: %s %s", r.Method, r.URL.Path)
		}
		return response([]byte(`{"data":[{"node":"proxmox","status":"online"}]}`))
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	nodes, err := client.Nodes(context.Background())
	if err != nil || len(nodes) != 1 || nodes[0].Node != "proxmox" {
		t.Fatalf("Nodes() = %#v, %v", nodes, err)
	}
}

func TestReloadNodeNetworkWaitsForPendingNetworkTask(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method == http.MethodPut && r.URL.Path == "/api2/json/nodes/proxmox/network" {
			return response([]byte(`{"data":"UPID:pve:reload-network"}`))
		}
		if r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/proxmox/tasks/UPID:pve:reload-network/status" {
			return response([]byte(`{"data":{"status":"stopped","exitstatus":"OK"}}`))
		}
		t.Fatalf("unexpected network reload request: %s %s", r.Method, r.URL.Path)
		return nil
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := client.ReloadNodeNetwork(context.Background(), "proxmox"); err != nil {
		t.Fatal(err)
	}
}

func TestResolveSingleNodeRejectsUnsupportedTopologyAndUnsafeIdentifiers(t *testing.T) {
	for _, test := range []struct {
		name  string
		nodes []Node
		want  string
	}{
		{name: "none", nodes: nil},
		{name: "cluster", nodes: []Node{{Node: "pve01"}, {Node: "pve02"}}},
		{name: "unsafe", nodes: []Node{{Node: "pve/01"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got, err := ResolveSingleNode(test.nodes); err == nil || got != test.want || !strings.Contains(err.Error(), "HOLD") {
				t.Fatalf("ResolveSingleNode() = %q, %v", got, err)
			}
		})
	}
	for _, node := range []string{"proxmox", "pve", "my-node_01.example"} {
		if got, err := ResolveSingleNode([]Node{{Node: node}}); err != nil || got != node {
			t.Fatalf("safe node %q rejected: %q, %v", node, got, err)
		}
	}
}

func TestQEMUAgentNetworkInterfacesUsesGuestAgentEndpoint(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method != http.MethodGet || r.URL.Path != "/api2/json/nodes/lab-proxmox-01/qemu/190/agent/network-get-interfaces" {
			t.Fatalf("unexpected guest-agent request: %s %s", r.Method, r.URL.Path)
		}
		return response([]byte(`{"data":{"result":[{"name":"eth0","hardware-address":"02:00:00:00:00:01","ip-addresses":[{"ip-address":"127.0.0.1","ip-address-type":"ipv4"},{"ip-address":"192.0.2.15","ip-address-type":"ipv4"}]}]}}`))
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

func TestCreateVMWaitsForProxmoxTaskBeforeReturning(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/qemu":
			return response([]byte(`{"data":"UPID:pve:create-vm"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/tasks/UPID:pve:create-vm/status":
			return response([]byte(`{"data":{"status":"stopped","exitstatus":"OK"}}`))
		default:
			t.Fatalf("unexpected VM creation request: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := client.CreateVM(context.Background(), "node", 190, url.Values{"name": {"lab-builder-01"}}); err != nil {
		t.Fatal(err)
	}
}

func TestCreateLXCWaitsForProxmoxTaskBeforeReturning(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/lxc":
			return response([]byte(`{"data":"UPID:pve:create-lxc"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/tasks/UPID:pve:create-lxc/status":
			return response([]byte(`{"data":{"status":"stopped","exitstatus":"OK"}}`))
		default:
			t.Fatalf("unexpected LXC creation request: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := client.CreateLXC(context.Background(), "node", 110, url.Values{"hostname": {"lab-dns-01"}}); err != nil {
		t.Fatal(err)
	}
}

func TestWaitTaskAcceptsProxmoxWarningCompletion(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method != http.MethodGet || r.URL.Path != "/api2/json/nodes/node/tasks/UPID:pve:create-lxc/status" {
			t.Fatalf("unexpected task status request: %s %s", r.Method, r.URL.Path)
		}
		return response([]byte(`{"data":{"status":"stopped","exitstatus":"WARNINGS: 1"}}`))
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := client.WaitTask(context.Background(), "node", "UPID:pve:create-lxc"); err != nil {
		t.Fatalf("WaitTask() rejected successful task warnings: %v", err)
	}
}

func TestResizeQEMUDiskUsesExplicitBoundedGrowth(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method != http.MethodPut || r.URL.Path != "/api2/json/nodes/node/qemu/190/resize" {
			t.Fatalf("unexpected resize request: %s %s", r.Method, r.URL.Path)
		}
		if err := r.ParseForm(); err != nil || r.Form.Get("disk") != "scsi0" || r.Form.Get("size") != "+32G" {
			t.Fatalf("unexpected resize form: %v", r.Form)
		}
		return response([]byte(`{"data":""}`))
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := client.ResizeQEMUDisk(context.Background(), "node", 190, "scsi0", 32); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteStorageSnippetRejectsPathsAndUsesExactEndpoint(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method != http.MethodDelete || r.URL.Path != "/api2/json/nodes/node/storage/local/content/snippets/boetticher-190-meta.yaml" {
			t.Fatalf("unexpected snippet deletion request: %s %s", r.Method, r.URL.Path)
		}
		return response([]byte(`{"data":null}`))
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := client.DeleteStorageSnippet(context.Background(), "node", "local", "boetticher-190-meta.yaml"); err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteStorageSnippet(context.Background(), "node", "local", "../other"); err == nil {
		t.Fatal("snippet deletion accepted a path")
	}
}

func TestDestroyQEMUPurgesBuilderConfigurationAndUnreferencedDisks(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method != http.MethodDelete || r.URL.Path != "/api2/json/nodes/node/qemu/190" {
			t.Fatalf("unexpected QEMU destruction request: %s %s", r.Method, r.URL.Path)
		}
		if r.URL.Query().Get("purge") != "1" || r.URL.Query().Get("destroy-unreferenced-disks") != "1" {
			t.Fatalf("QEMU destruction did not request bounded cleanup: %v", r.URL.Query())
		}
		return response([]byte(`{"data":null}`))
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := client.DestroyQEMU(context.Background(), "node", 190); err != nil {
		t.Fatal(err)
	}
	if err := client.DestroyQEMU(context.Background(), "node", 0); err == nil {
		t.Fatal("invalid QEMU destruction identity was accepted")
	}
}

func TestDestroyLXCPurgesConfigurationAndUnreferencedVolumes(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method != http.MethodDelete || r.URL.Path != "/api2/json/nodes/node/lxc/200" {
			t.Fatalf("unexpected LXC destruction request: %s %s", r.Method, r.URL.Path)
		}
		if r.URL.Query().Get("purge") != "1" || r.URL.Query().Get("destroy-unreferenced-disks") != "1" {
			t.Fatalf("LXC destruction did not request bounded cleanup: %v", r.URL.Query())
		}
		return response([]byte(`{"data":null}`))
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := client.DestroyLXC(context.Background(), "node", 200); err != nil {
		t.Fatal(err)
	}
	if err := client.DestroyLXC(context.Background(), "node", 0); err == nil {
		t.Fatal("invalid LXC destruction identity was accepted")
	}
}

func TestDestroyLXCWaitsForAsynchronousDeletion(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method == http.MethodDelete && r.URL.Path == "/api2/json/nodes/node/lxc/910" {
			return response([]byte(`{"data":"UPID:pve:destroy-lxc"}`))
		}
		if r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/tasks/UPID:pve:destroy-lxc/status" {
			return response([]byte(`{"data":{"status":"stopped","exitstatus":"OK"}}`))
		}
		t.Fatalf("unexpected LXC deletion request: %s %s", r.Method, r.URL.Path)
		return nil
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := client.DestroyLXC(context.Background(), "node", 910); err != nil {
		t.Fatalf("DestroyLXC() did not wait for the deletion task: %v", err)
	}
}

func TestQEMUStatusUsesLiveStatusEndpoint(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method != http.MethodGet || r.URL.Path != "/api2/json/nodes/node/qemu/190/status/current" {
			t.Fatalf("unexpected QEMU status request: %s %s", r.Method, r.URL.Path)
		}
		return response([]byte(`{"data":{"status":"running"}}`))
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	status, err := client.QEMUStatus(context.Background(), "node", 190)
	if err != nil || status != "running" {
		t.Fatalf("QEMUStatus() = %q, %v", status, err)
	}
}

func TestEnsureVMRunningDoesNotRestartRunningVM(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method != http.MethodGet || r.URL.Path != "/api2/json/nodes/node/qemu/100/status/current" {
			t.Fatalf("unexpected request while checking running VM: %s %s", r.Method, r.URL.Path)
		}
		return response([]byte(`{"data":{"status":"running"}}`))
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := client.EnsureVMRunning(context.Background(), "node", 100); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureLXCRunningDoesNotRestartRunningContainer(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method != http.MethodGet || r.URL.Path != "/api2/json/nodes/node/lxc/110/status/current" {
			t.Fatalf("unexpected request while checking running LXC: %s %s", r.Method, r.URL.Path)
		}
		return response([]byte(`{"data":{"status":"running"}}`))
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := client.EnsureLXCRunning(context.Background(), "node", 110); err != nil {
		t.Fatal(err)
	}
}

func TestDestroyBuilderStopsRunningOwnedVMBeforeRemoval(t *testing.T) {
	stopped := false
	removed := false
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/190/config":
			if removed {
				return apiResponse(http.StatusNotFound, `{"errors":{"vmid":"not found"}}`)
			}
			return response([]byte(`{"data":{"name":"lab-builder-01","tags":"boetticher;boetticher-builder"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/190/status/current":
			if stopped {
				return response([]byte(`{"data":{"status":"stopped"}}`))
			}
			return response([]byte(`{"data":{"status":"running"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/qemu/190/status/stop":
			stopped = true
			return response([]byte(`{"data":null}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/api2/json/nodes/node/qemu/190":
			if !stopped {
				t.Fatalf("builder removal was requested before stop")
			}
			removed = true
			return response([]byte(`{"data":null}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/lxc/190/config":
			return apiResponse(http.StatusNotFound, `{"errors":{"vmid":"not found"}}`)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api2/json/nodes/node/storage/local/content/snippets/boetticher-190-"):
			return response([]byte(`{"data":null}`))
		default:
			t.Fatalf("unexpected builder cleanup request: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := DestroyBuilderVM(context.Background(), client, "node"); err != nil {
		t.Fatalf("DestroyBuilderVM() = %v", err)
	}
	if !stopped || !removed {
		t.Fatalf("builder cleanup state stopped=%t removed=%t", stopped, removed)
	}
}

func TestDestroyBuilderDetachesOnlyCanonicalCacheAndPreservesUnreferencedDisks(t *testing.T) {
	stopped := false
	removed := false
	detached := false
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/190/config":
			if removed {
				return apiResponse(http.StatusNotFound, `{"errors":{"vmid":"not found"}}`)
			}
			return response([]byte(`{"data":{"name":"lab-builder-01","tags":"boetticher;boetticher-builder","scsi1":"local-lvm:vm-191-boetticher-builder-cache,format=raw,serial=boetticher-builder-cache"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/qemu/190/status/current":
			if stopped {
				return response([]byte(`{"data":{"status":"stopped"}}`))
			}
			return response([]byte(`{"data":{"status":"running"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/qemu/190/status/stop":
			stopped = true
			return response([]byte(`{"data":null}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/qemu/190/config":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.Form.Get("delete") != "scsi1" {
				t.Fatalf("unexpected builder disk detach form: %v", r.Form)
			}
			detached = true
			return response([]byte(`{"data":null}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/api2/json/nodes/node/qemu/190":
			if !stopped || !detached {
				t.Fatalf("builder removal occurred before stop/detach: stopped=%t detached=%t", stopped, detached)
			}
			if r.URL.Query().Get("purge") != "1" || r.URL.Query().Get("destroy-unreferenced-disks") != "0" {
				t.Fatalf("builder removal would destroy unreferenced disks: %s", r.URL.RawQuery)
			}
			removed = true
			return response([]byte(`{"data":null}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/lxc/190/config":
			return apiResponse(http.StatusNotFound, `{"errors":{"vmid":"not found"}}`)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api2/json/nodes/node/storage/local/content/snippets/boetticher-190-"):
			return response([]byte(`{"data":null}`))
		default:
			t.Fatalf("unexpected builder cache cleanup request: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := DestroyBuilderVM(context.Background(), client, "node"); err != nil {
		t.Fatalf("DestroyBuilderVM() = %v", err)
	}
	if !stopped || !detached || !removed {
		t.Fatalf("builder cleanup state stopped=%t detached=%t removed=%t", stopped, detached, removed)
	}
}

func TestUploadStorageFileUsesMultipartArtifactContract(t *testing.T) {
	path := t.TempDir() + "/artifact.tar.zst"
	content := []byte("artifact bytes")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	checksum := sha256.Sum256(content)
	wantChecksum := hex.EncodeToString(checksum[:])
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method != http.MethodPost || r.URL.Path != "/api2/json/nodes/lab-proxmox-01/storage/local/upload" {
			t.Fatalf("unexpected upload request: %s %s", r.Method, r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data;") {
			t.Fatalf("upload was not multipart: %q", r.Header.Get("Content-Type"))
		}
		if r.ContentLength <= 0 || len(r.TransferEncoding) != 0 {
			t.Fatalf("upload framing is not length-delimited: content-length=%d transfer-encoding=%v", r.ContentLength, r.TransferEncoding)
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Fatal(err)
		}
		if got := r.FormValue("content"); got != "vztmpl" {
			t.Fatalf("content = %q, want vztmpl", got)
		}
		if got := r.FormValue("checksum"); got != wantChecksum || r.FormValue("checksum-algorithm") != "sha256" {
			t.Fatalf("checksum fields = %q/%q", got, r.FormValue("checksum-algorithm"))
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
	if err := client.UploadStorageFile(context.Background(), "lab-proxmox-01", "local", "vztmpl", path, "boetticher-logging-1.0.0-amd64.tar.zst", wantChecksum); err != nil {
		t.Fatal(err)
	}
}

func TestUploadStorageFileStreamsLargeArtifactBody(t *testing.T) {
	artifactPath := filepath.Join(t.TempDir(), "large-artifact.tar.zst")
	artifact, err := os.Create(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := artifact.Truncate(32 << 20); err != nil {
		_ = artifact.Close()
		t.Fatal(err)
	}
	if err := artifact.Close(); err != nil {
		t.Fatal(err)
	}
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.GetBody != nil {
			t.Fatal("streamed multipart request unexpectedly exposes a replayable buffered body")
		}
		if r.ContentLength <= 0 || len(r.TransferEncoding) != 0 {
			t.Fatalf("large upload framing is not length-delimited: content-length=%d transfer-encoding=%v", r.ContentLength, r.TransferEncoding)
		}
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Fatal(err)
		}
		return response([]byte(`{"data":null}`))
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	checksum := sha256.Sum256(make([]byte, 32<<20))
	if err := client.UploadStorageFile(context.Background(), "node", "local", "vztmpl", artifactPath, "large-artifact.tar.zst", hex.EncodeToString(checksum[:])); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureDirectoryStorageCreatesBackupStorage(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method == http.MethodGet && r.URL.Path == "/api2/json/storage" {
			return response([]byte(`{"data":[]}`))
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api2/json/storage" {
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
		if r.Method == http.MethodGet && r.URL.Path == "/api2/json/storage" {
			return response([]byte(`{"data":[{"storage":"local","type":"dir","path":"/var/lib/vz","content":"backup,iso,vztmpl"}]}`))
		}
		if r.Method == http.MethodPut && r.URL.Path == "/api2/json/storage/local" {
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
			"content": "import", "filename": "debian-13.qcow2", "url": "https://images.example/debian-13.qcow2", "checksum": checksum, "checksum-algorithm": "sha512",
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

func TestEnsureCloudImageAcceptsPVEImportWithoutListingChecksumAfterVerifiedDownload(t *testing.T) {
	checksum := strings.Repeat("a", 128)
	var contentRequests int
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/storage/local/content":
			contentRequests++
			if contentRequests == 1 {
				return response([]byte(`{"data":[{"content":"import","volid":"local:import/image.qcow2","format":"qcow2","size":42}]}`))
			}
			return response([]byte(`{"data":[{"content":"import","volid":"local:import/image.qcow2","format":"qcow2","size":42}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/node/storage/local/download-url":
			return response([]byte(`{"data":"UPID:pve:download"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/node/tasks/UPID:pve:download/status":
			return response([]byte(`{"data":{"status":"stopped","exitstatus":"OK"}}`))
		default:
			t.Fatalf("unexpected cloud image request: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	volID, err := client.EnsureCloudImage(context.Background(), "node", "local", "image.qcow2", "https://images.example/image.qcow2", checksum)
	if err != nil || volID != "local:import/image.qcow2" {
		t.Fatalf("EnsureCloudImage() = %q, %v", volID, err)
	}
}

func TestUploadStorageTextUsesAuthenticatedSSHForSnippets(t *testing.T) {
	runner := &fakeRunner{}
	client := &Client{snippetRunner: runner, snippetAddr: "192.0.2.10", snippetUser: "root"}
	if err := client.UploadStorageText(context.Background(), "node", "local", "snippets", "boetticher-190-meta.yaml", "instance-id: trial\n"); err != nil {
		t.Fatal(err)
	}
	if runner.address != "192.0.2.10" || runner.user != "root" || !strings.Contains(runner.command, "/var/lib/vz/snippets/boetticher-190-meta.yaml") {
		t.Fatalf("unexpected SSH snippet upload: %#v", runner)
	}
}

func TestDownloadURLRejectsUnpinnedOrUnsafeInputs(t *testing.T) {
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: roundTripFunc(func(r *http.Request) *http.Response { return response([]byte(`{"data":"unexpected"}`)) })}}
	if _, err := client.DownloadURL(context.Background(), "node", "local", "../image.qcow2", "https://images.example/image.qcow2", strings.Repeat("a", 128)); err == nil {
		t.Fatal("unsafe image filename was accepted")
	}
	if _, err := client.DownloadURL(context.Background(), "node", "local", "image.qcow2", "http://images.example/image.qcow2", strings.Repeat("a", 128)); err == nil {
		t.Fatal("HTTP image URL was accepted")
	}
	if _, err := client.DownloadURL(context.Background(), "node", "local", "image.qcow2", "https://images.example/image.qcow2", "not-a-sha512"); err == nil {
		t.Fatal("unverified image checksum was accepted")
	}
}

func TestImportDiskUsesTheSupportedQEMUImportFromConfig(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		if r.Method != http.MethodPost || r.URL.Path != "/api2/json/nodes/node/qemu/100/config" {
			t.Fatalf("unexpected import request: %s %s", r.Method, r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if got := r.Form.Get("scsi0"); got != "boetticher-thin:0,import-from=local:iso/debian-13.qcow2,format=qcow2" {
			t.Errorf("scsi0 = %q", got)
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

func TestIsNotFoundAcceptsProxmoxMissingGuestConfigResponse(t *testing.T) {
	err := &APIError{
		StatusCode: http.StatusInternalServerError,
		Message:    "Configuration file 'nodes/proxmox/qemu-server/190.conf' does not exist\n",
	}
	if !IsNotFound(err) {
		t.Fatal("Proxmox missing guest configuration was not classified as not found")
	}
	if IsNotFound(&APIError{StatusCode: http.StatusInternalServerError, Message: "storage backend failed"}) {
		t.Fatal("unrelated Proxmox HTTP 500 was classified as not found")
	}
}

func apiResponse(status int, data string) *http.Response {
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Header: make(http.Header), Body: io.NopCloser(strings.NewReader(data))}
}
