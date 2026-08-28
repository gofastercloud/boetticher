package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gofastercloud/boetticher/internal/aiops"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "status" {
		store, err := aiops.OpenStore("/var/lib/boetticher/aiops/incidents.db")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer store.Close()
		status, err := store.Status(context.Background(), time.Now())
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := json.NewEncoder(os.Stdout).Encode(status); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	credentials := os.Getenv("CREDENTIALS_DIRECTORY")
	webhook, err := aiops.ReadCredential(credentials, "webhook-secret")
	if err != nil {
		return fmt.Errorf("load webhook credential: %w", err)
	}
	store, err := aiops.OpenStore("/var/lib/boetticher/aiops/incidents.db")
	if err != nil {
		return err
	}
	defer store.Close()
	pulseToken, err := aiops.ReadCredential(credentials, "pulse-read-token")
	if err != nil {
		return fmt.Errorf("load Pulse read credential: %w", err)
	}
	pulseClient, err := mtlsClient(credentials, "pulse-read-cert", "pulse-read-key")
	if err != nil {
		return fmt.Errorf("configure Pulse read client: %w", err)
	}
	noteToken, err := aiops.ReadCredential(credentials, "pulse-note-token")
	if err != nil {
		return fmt.Errorf("load Pulse note credential: %w", err)
	}
	noteClient, err := mtlsClient(credentials, "pulse-note-cert", "pulse-note-key")
	if err != nil {
		return fmt.Errorf("configure Pulse note client: %w", err)
	}
	pulse := aiops.PulseClient{Read: pulseClient, ReadToken: string(pulseToken), Note: noteClient, NoteToken: string(noteToken), BaseURL: os.Getenv("AIOPS_PULSE_URL")}
	if err := pulse.Validate(); err != nil {
		return err
	}
	journalClient, err := mtlsClient(credentials, "log-query-client-cert", "log-query-client-key")
	if err != nil {
		return fmt.Errorf("configure journal query client: %w", err)
	}
	routerClient, err := mtlsClient(credentials, "ai-router-client-cert", "ai-router-client-key")
	if err != nil {
		return fmt.Errorf("configure AI Router client: %w", err)
	}
	evidence := aiops.RemoteEvidence{
		Pulse: pulseClient, PulseBaseURL: os.Getenv("AIOPS_PULSE_URL"), PulseToken: string(pulseToken),
		Journal: journalClient, JournalURL: os.Getenv("AIOPS_JOURNAL_URL"),
	}
	if err := evidence.Validate(); err != nil {
		return err
	}
	capabilities := aiops.NewCapabilityRegistry()
	broker := &aiops.Broker{
		Capabilities: capabilities, Evidence: evidence, Router: routerClient,
		RouterURL: os.Getenv("AIOPS_ROUTER_URL"), ModelAlias: os.Getenv("AIOPS_MODEL_ALIAS"), RouterIdentity: "boetticher-holmes-active-investigation",
	}
	if err := broker.Validate(); err != nil {
		return err
	}
	catalog, err := aiops.LoadEvidenceCatalog("/etc/boetticher-aiops/evidence-policy.json")
	if err != nil {
		return fmt.Errorf("load evidence catalog: %w", err)
	}
	worker := &aiops.Worker{
		Store: store, Capabilities: capabilities,
		Investigator: aiops.HolmesClient{Client: aiops.NewBoundedHTTPClient(http.DefaultTransport), URL: "http://127.0.0.1:8090/api/chat"},
		Policy:       catalog.Policy,
	}
	evidenceListener, err := net.Listen("tcp4", "127.0.0.1:8443")
	if err != nil {
		return fmt.Errorf("bind evidence broker: %w", err)
	}
	defer evidenceListener.Close()
	routerListener, err := net.Listen("tcp4", "127.0.0.1:8444")
	if err != nil {
		return fmt.Errorf("bind model broker: %w", err)
	}
	defer routerListener.Close()
	externalListener, err := activationListener()
	if err != nil {
		return err
	}
	defer externalListener.Close()
	certificate, err := tls.LoadX509KeyPair(credentials+"/server-cert", credentials+"/server-key")
	if err != nil {
		return fmt.Errorf("load AIOps server identity: %w", err)
	}
	externalServer := &http.Server{
		Handler:           (&aiops.Server{Store: store, WebhookSecret: webhook, OnResolved: worker.Cancel}).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
	servers := []struct {
		name     string
		server   *http.Server
		listener net.Listener
	}{
		{"evidence broker", boundedServer(broker.EvidenceHandler()), evidenceListener},
		{"model broker", boundedServer(broker.RouterHandler()), routerListener},
		{"AIOps listener", externalServer, tls.NewListener(externalListener, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}})},
	}
	serveErrors := make(chan error, len(servers))
	for _, configured := range servers {
		go func() {
			err := configured.server.Serve(configured.listener)
			if err == nil || err == http.ErrServerClosed {
				serveErrors <- fmt.Errorf("%s stopped unexpectedly", configured.name)
				return
			}
			serveErrors <- fmt.Errorf("%s failed: %w", configured.name, err)
		}()
	}
	go runWorker(worker)
	go runPulseOperations(store, worker, pulse)
	return <-serveErrors
}

func boundedServer(handler http.Handler) *http.Server {
	return &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
}

func runPulseOperations(store *aiops.Store, worker *aiops.Worker, pulse aiops.PulseClient) {
	poll := time.NewTicker(60 * time.Second)
	notes := time.NewTicker(time.Second)
	defer poll.Stop()
	defer notes.Stop()
	for {
		select {
		case now := <-poll.C:
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			alerts, err := pulse.ActiveAlerts(ctx)
			if err == nil {
				resolved, reconcileErr := store.Reconcile(ctx, alerts, now)
				if reconcileErr == nil {
					for _, incidentID := range resolved {
						worker.Cancel(incidentID)
					}
				}
			}
			cancel()
		case <-notes.C:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			note, ok, err := store.NextPendingNote(ctx)
			if err == nil && ok {
				delivered := pulse.WriteNote(ctx, note) == nil
				errorCode := ""
				if !delivered {
					errorCode = "delivery_failed"
				}
				_ = store.RecordNoteAttempt(ctx, note, delivered, errorCode)
			}
			cancel()
		}
	}
}

func runWorker(worker *aiops.Worker) {
	ticker := time.NewTicker(time.Second)
	prune := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	defer prune.Stop()
	for {
		select {
		case <-ticker.C:
			if _, err := worker.RunOnce(context.Background()); err != nil {
				fmt.Fprintln(os.Stderr, "AIOps worker transition failed")
			}
		case now := <-prune.C:
			if err := worker.Store.Prune(context.Background(), now); err != nil {
				fmt.Fprintln(os.Stderr, "AIOps retention prune failed")
			}
		}
	}
}

func mtlsClient(directory, certificateName, keyName string) (*http.Client, error) {
	certificate, err := tls.LoadX509KeyPair(directory+"/"+certificateName, directory+"/"+keyName)
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(directory + "/client-ca")
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("client CA contains no certificates")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{certificate}}, DisableCompression: true, MaxIdleConnsPerHost: 2, ResponseHeaderTimeout: 10 * time.Second}
	return aiops.NewBoundedHTTPClient(transport), nil
}

func activationListener() (net.Listener, error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) || os.Getenv("LISTEN_FDS") != "1" {
		return nil, fmt.Errorf("exactly one systemd socket-activated listener is required")
	}
	file := os.NewFile(3, "aiops-listener")
	if file == nil {
		return nil, fmt.Errorf("systemd listener fd is unavailable")
	}
	return net.FileListener(file)
}
