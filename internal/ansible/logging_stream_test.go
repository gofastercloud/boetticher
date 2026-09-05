package ansible

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJournalUploadProxyStreamsAuthenticatedRequests(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "ansible", "roles", "logging", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	block := ansibleTaskBlock(string(data), "Install the revocation-enforcing journal mTLS proxy")
	for _, required := range []string{"location = /upload", "client_max_body_size 0;", "proxy_request_buffering off;", "proxy_http_version 1.1;", "ssl_verify_client on;", "ssl_crl", "boetticher_logging_client_allowed = 0"} {
		if !strings.Contains(block, required) {
			t.Fatalf("journal stream contract missing %q", required)
		}
	}
}
