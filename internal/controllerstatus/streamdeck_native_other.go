//go:build !linux

package controllerstatus

import (
	"context"
	"errors"

	decklib "github.com/matthewpi/streamdeck"
)

func openNativeDeck(context.Context, StreamDeckConfig) (*decklib.Device, error) {
	return nil, errors.New("StreamDeck USB support is only available on Linux")
}
