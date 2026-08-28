package main

import (
	"context"
	"crypto/tls"
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
