package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/gofastercloud/boetticher/internal/firewall"
	"github.com/gofastercloud/boetticher/internal/firewalltelemetry"
)

func main() {
	store, err := firewalltelemetry.OpenStore(firewall.TelemetryDatabasePath)
	if err != nil {
		log.Fatalf("open firewall telemetry store: %v", err)
	}
	defer store.Close()

	service, err := firewalltelemetry.New(firewalltelemetry.Config{
		SnapshotPath:   firewall.TelemetrySnapshotPath,
		ListenAddress:  firewall.TelemetryListenAddress,
		Port:           firewall.TelemetryPort,
		Interval:       time.Duration(firewall.TelemetrySampleIntervalSec) * time.Second,
		AllowedSources: []string{firewall.TelemetryPulseSource},
	}, store)
	if err != nil {
		log.Fatalf("configure firewall telemetry: %v", err)
	}
	server := &http.Server{
		Addr:              net.JoinHostPort(firewall.TelemetryListenAddress, strconv.Itoa(firewall.TelemetryPort)),
		Handler:           service.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    firewalltelemetry.MaxHeaderBytes,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		if err := service.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("firewall telemetry collector stopped: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("firewall telemetry API: %v", err)
	}
}
