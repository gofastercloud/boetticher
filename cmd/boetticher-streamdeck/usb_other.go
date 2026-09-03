//go:build !linux

package main

import (
	"fmt"

	"github.com/gofastercloud/boetticher/internal/streamdeck"
)

func streamDeckDevicePath(streamdeck.Config) (string, error) {
	return "", fmt.Errorf("StreamDeck USB discovery is only supported on Linux")
}

func reconnectStreamDeckUSB(streamdeck.Config) error {
	return fmt.Errorf("StreamDeck USB driver recovery is only supported on Linux")
}
