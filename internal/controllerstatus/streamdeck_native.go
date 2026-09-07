package controllerstatus

import (
	"context"
)

func NewNativeStreamDeckFactory(config StreamDeckConfig, brightness float64) StreamDeckFactory {
	return func(ctx context.Context) (StreamDeck, error) {
		return openNativeStreamDeck(ctx, config, brightness)
	}
}
