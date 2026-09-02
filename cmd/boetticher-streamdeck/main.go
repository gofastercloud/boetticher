package main

import (
	"context"
	"errors"
	"fmt"
	"image"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/gofastercloud/boetticher/internal/streamdeck"
	decklib "github.com/matthewpi/streamdeck"
)

type nativeDeck struct {
	deck *decklib.StreamDeck
}

func (d *nativeDeck) ButtonCount() int { return d.deck.Device().ButtonCount() }
func (d *nativeDeck) ImageSize() int   { return d.deck.Device().ImageSize }
func (d *nativeDeck) SetBrightness(ctx context.Context, value uint8) error {
	return d.deck.SetBrightness(ctx, value)
}
func (d *nativeDeck) ProcessImage(image image.Image) ([]byte, error) {
	return d.deck.ProcessImage(image)
}
func (d *nativeDeck) SetButton(ctx context.Context, index int, data []byte) error {
	return d.deck.Device().SetButton(ctx, index, data)
}
func (d *nativeDeck) Close(ctx context.Context) error { return d.deck.Close(ctx) }

func openDeck(ctx context.Context, _ string) (streamdeck.Deck, error) {
	device, err := openRawDeck(ctx, decklib.Open, reconnectStreamDeckUSB)
	if err != nil {
		return nil, err
	}
	if device == nil {
		return nil, errors.New("no supported StreamDeck found")
	}
	deck, err := decklib.NewFromDevice(ctx, device)
	if err != nil {
		return nil, err
	}
	return &nativeDeck{deck: deck}, nil
}

func openRawDeck(ctx context.Context, open func(context.Context) (*decklib.Device, error), reconnect func() error) (*decklib.Device, error) {
	device, err := open(ctx)
	if !errors.Is(err, syscall.ENODATA) {
		return device, err
	}
	if err := reconnect(); err != nil {
		return nil, fmt.Errorf("reconnect unbound StreamDeck USB driver: %w", err)
	}
	return open(ctx)
}

func main() {
	configFile, err := os.Open(streamdeck.ConfigPath)
	if err != nil {
		slog.Error("open StreamDeck configuration", "error", err)
		os.Exit(1)
	}
	config, err := streamdeck.LoadConfig(configFile)
	_ = configFile.Close()
	if err != nil {
		slog.Error("load StreamDeck configuration", "error", err)
		os.Exit(1)
	}
	credentialDirectory := strings.TrimSpace(os.Getenv("CREDENTIALS_DIRECTORY"))
	if credentialDirectory == "" {
		slog.Error("StreamDeck Pulse credential directory is unavailable")
		os.Exit(1)
	}
	token, err := os.ReadFile(credentialDirectory + "/pulse-token")
	if err != nil {
		slog.Error("read StreamDeck Pulse credential", "error", err)
		os.Exit(1)
	}
	client, err := streamdeck.NewPulseClient(config, strings.TrimSpace(string(token)))
	if err != nil {
		slog.Error("create StreamDeck Pulse client", "error", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := streamdeck.Run(ctx, config, client, openDeck); err != nil {
		slog.Error("StreamDeck runtime stopped", "error", fmt.Sprintf("%T", err))
	}
}
