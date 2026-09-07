package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

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
	flag.Parse()
	if flag.NArg() != 0 {
		fail("unexpected positional argument")
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
