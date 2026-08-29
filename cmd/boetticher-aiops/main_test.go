package main

import (
	"context"
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

func TestAIOpsBackgroundLoopsHonorCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	workerDone := make(chan struct{})
	go func() {
		runWorker(ctx, nil)
		close(workerDone)
	}()
	pulseDone := make(chan struct{})
	go func() {
		runPulseOperations(ctx, nil, nil, aiops.PulseClient{})
		close(pulseDone)
	}()
	select {
	case <-workerDone:
	case <-time.After(time.Second):
		t.Fatal("AIOps worker did not stop after cancellation")
	}
	select {
	case <-pulseDone:
	case <-time.After(time.Second):
		t.Fatal("AIOps Pulse loop did not stop after cancellation")
	}
}
