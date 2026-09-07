package controllerstatus

import (
	"context"
	"log"
	"time"
)

const (
	streamDeckRetryInterval = 3 * time.Second
	streamDeckWriteInterval = 10 * time.Second
)

// runStreamDeck owns the device lifecycle and all USB writes. The daemon only
// sends the latest rendered frame and receives bounded key events.
func runStreamDeck(ctx context.Context, factory StreamDeckFactory, frames <-chan []KeyImage, events chan<- KeyEvent, logger *log.Logger) {
	if factory == nil {
		return
	}
	var deck StreamDeck
	var latest []KeyImage
	retryAt := time.Time{}
	heartbeat := time.NewTicker(streamDeckWriteInterval)
	defer heartbeat.Stop()
	for {
		if deck == nil && !time.Now().Before(retryAt) {
			openCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			candidate, err := factory(openCtx)
			cancel()
			if err != nil || candidate == nil {
				if err != nil && logger != nil {
					logger.Printf("StreamDeck unavailable; retrying: %v", err)
				}
				retryAt = time.Now().Add(streamDeckRetryInterval)
			} else {
				deck = candidate
				if logger != nil {
					logger.Printf("StreamDeck connected")
				}
				if err := writeStreamDeckFrame(ctx, deck, latest); err != nil {
					closeStreamDeck(deck, logger)
					deck = nil
					retryAt = time.Now().Add(streamDeckRetryInterval)
				}
			}
		}

		var deviceEvents <-chan KeyEvent
		if deck != nil {
			deviceEvents = deck.Events()
		}
		select {
		case <-ctx.Done():
			if deck != nil {
				_ = deck.Clear(context.Background())
				closeStreamDeck(deck, logger)
			}
			return
		case frame := <-frames:
			latest = frame
			if deck != nil {
				if err := writeStreamDeckFrame(ctx, deck, latest); err != nil {
					closeStreamDeck(deck, logger)
					deck = nil
					retryAt = time.Now().Add(streamDeckRetryInterval)
				}
			}
		case event, ok := <-deviceEvents:
			if !ok {
				closeStreamDeck(deck, logger)
				deck = nil
				retryAt = time.Now().Add(streamDeckRetryInterval)
				continue
			}
			select {
			case events <- event:
			default:
			}
		case <-heartbeat.C:
			if deck != nil {
				if err := writeStreamDeckFrame(ctx, deck, latest); err != nil {
					closeStreamDeck(deck, logger)
					deck = nil
					retryAt = time.Now().Add(streamDeckRetryInterval)
				}
			}
		}
	}
}

func writeStreamDeckFrame(ctx context.Context, deck StreamDeck, frame []KeyImage) error {
	if len(frame) == 0 {
		return nil
	}
	for index, key := range frame {
		if err := deck.SetKey(ctx, index, key); err != nil {
			return err
		}
	}
	return nil
}

func closeStreamDeck(deck StreamDeck, logger *log.Logger) {
	if deck == nil {
		return
	}
	if err := deck.Close(); err != nil && logger != nil {
		logger.Printf("StreamDeck closed with error: %v", err)
	}
}
