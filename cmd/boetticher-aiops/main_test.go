package main

import (
	"net/http"
	"testing"
	"time"

	"github.com/gofastercloud/boetticher/internal/aiops"
)

func TestModelBrokerServerAllowsInvestigationTimeout(t *testing.T) {
	server := modelBrokerServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if server.WriteTimeout < aiops.MaxInvestigationTime {
		t.Fatalf("model broker write timeout = %s, want at least %s", server.WriteTimeout, aiops.MaxInvestigationTime)
	}
	if server.WriteTimeout <= 30*time.Second {
		t.Fatalf("model broker retained the short evidence timeout: %s", server.WriteTimeout)
	}
}
