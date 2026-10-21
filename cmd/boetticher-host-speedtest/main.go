package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gofastercloud/boetticher/internal/labspeedtest"
	"github.com/showwin/speedtest-go/speedtest"
	"github.com/showwin/speedtest-go/speedtest/transport"
)

type result struct {
	Version       string  `json:"version"`
	Server        string  `json:"server"`
	LatencyMS     float64 `json:"latency_ms"`
	JitterMS      float64 `json:"jitter_ms"`
	DownloadMbps  float64 `json:"download_mbps"`
	UploadMbps    float64 `json:"upload_mbps"`
	PacketLossPct float64 `json:"packet_loss_pct"`
}

func main() {
	source := flag.String("source", "vmbr0", "source interface for the Host test")
	jsonOutput := flag.Bool("json", false, "emit the machine-readable result")
	version := flag.Bool("version", false, "print the helper contract version")
	lab := flag.Bool("lab", false, "measure LAB egress from a temporary SERVERS namespace behind the firewall")
	stream := flag.Bool("stream", false, "emit one JSON progress event per line (lab mode)")
	cleanupOnly := flag.Bool("cleanup-only", false, "remove an owned lab fixture left by an interrupted run (lab mode)")
	labChild := flag.Bool("lab-child", false, "internal: measure from inside the owned lab namespace")
	gateway := flag.String("gateway", "", "internal: lab namespace gateway and resolver")
	flag.Parse()
	if flag.NArg() != 0 {
		fail("unexpected positional argument")
	}
	switch {
	case *version:
		fmt.Println(labspeedtest.HelperVersion)
		return
	case *labChild:
		if *lab || *stream || *cleanupOnly || *jsonOutput || *gateway != labspeedtest.Gateway {
			fail("--lab-child requires only the fixed lab gateway")
		}
		os.Exit(runLabChild(*gateway, os.Stdout))
	case *lab && *cleanupOnly:
		if *stream || *jsonOutput || *gateway != "" {
			fail("--lab --cleanup-only takes no other options")
		}
		os.Exit(runLabCleanup(os.Stdout))
	case *lab:
		if !*stream || *jsonOutput || *gateway != "" {
			fail("--lab requires --stream")
		}
		os.Exit(runLab(os.Stdout))
	case *cleanupOnly:
		fail("--cleanup-only requires --lab")
	}
	if !*jsonOutput {
		fail("--json is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	client := speedtest.New(
		speedtest.WithDoer(&http.Client{Timeout: 20 * time.Second}),
		speedtest.WithUserConfig(&speedtest.UserConfig{
			Source:         *source,
			PingMode:       speedtest.TCP,
			MaxConnections: 8,
			UserAgent:      "boetticher-host-speedtest/1",
		}),
	)
	servers, err := client.FetchServerListContext(ctx)
	if err != nil {
		fail("fetch speedtest servers: %v", err)
	}
	targets, err := servers.FindServer(nil)
	if err != nil || len(targets) == 0 {
		fail("select speedtest server: %v", err)
	}
	server := targets[0]
	if err := server.PingTestContext(ctx, nil); err != nil {
		fail("speedtest ping: %v", err)
	}

	packetLossCtx, packetLossCancel := context.WithTimeout(ctx, 40*time.Second)
	packetLossDone := make(chan error, 1)
	analyzer := speedtest.NewPacketLossAnalyzer(&speedtest.PacketLossAnalyzerOptions{SourceInterface: *source})
	go func() {
		packetLossDone <- analyzer.RunWithContext(packetLossCtx, server.Host, func(packetLoss *transport.PLoss) {
			server.PacketLoss = *packetLoss
		})
	}()

	if err := server.DownloadTestContext(ctx); err != nil {
		packetLossCancel()
		fail("speedtest download: %v", err)
	}
	if err := server.UploadTestContext(ctx); err != nil {
		packetLossCancel()
		fail("speedtest upload: %v", err)
	}
	packetLossCancel()
	if err := <-packetLossDone; err != nil && err != transport.ErrUnsupported {
		fail("speedtest packet loss: %v", err)
	}

	output := result{
		Version:       speedtest.Version(),
		Server:        server.String(),
		LatencyMS:     server.Latency.Seconds() * 1000,
		JitterMS:      server.Jitter.Seconds() * 1000,
		DownloadMbps:  float64(server.DLSpeed) * 8 / 1_000_000,
		UploadMbps:    float64(server.ULSpeed) * 8 / 1_000_000,
		PacketLossPct: server.PacketLoss.LossPercent(),
	}
	if err := json.NewEncoder(os.Stdout).Encode([]result{output}); err != nil {
		fail("encode speedtest result: %v", err)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "boetticher-host-speedtest: "+format+"\n", args...)
	os.Exit(1)
}
