//go:build !linux

package controllerstatus

import (
	"context"
	"errors"
)

func openNativeStreamDeck(context.Context, StreamDeckConfig, float64) (StreamDeck, error) {
	return nil, errors.New("StreamDeck USB support is only available on Linux")
}
