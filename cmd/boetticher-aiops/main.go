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
	broker := &aiops.Broker{
		Capabilities: aiops.NewCapabilityRegistry(), Evidence: evidence, Router: routerClient,
		RouterURL: os.Getenv("AIOPS_ROUTER_URL"), ModelAlias: os.Getenv("AIOPS_MODEL_ALIAS"),
	}
	if err := broker.Validate(); err != nil {
		return err
	}
	for _, loopback := range []struct {
		address string
		handler http.Handler
	}{{"127.0.0.1:8443", broker.EvidenceHandler()}, {"127.0.0.1:8444", broker.RouterHandler()}} {
		server := &http.Server{Addr: loopback.address, Handler: loopback.handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
		go func() {
			if serveErr := server.ListenAndServe(); serveErr != nil && serveErr != http.ErrServerClosed {
				fmt.Fprintln(os.Stderr, "loopback broker failed")
				os.Exit(1)
			}
		}()
	}
	listener, err := activationListener()
	if err != nil {
		return err
	}
	certificate, err := tls.LoadX509KeyPair(credentials+"/server-cert", credentials+"/server-key")
	if err != nil {
		return fmt.Errorf("load AIOps server identity: %w", err)
	}
	server := &http.Server{
		Handler:           (&aiops.Server{Store: store, WebhookSecret: webhook}).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
	return server.Serve(tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}))
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
