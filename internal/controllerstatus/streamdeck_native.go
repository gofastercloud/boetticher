package controllerstatus

import (
	"context"
	"errors"
	"fmt"
	"time"

	decklib "github.com/matthewpi/streamdeck"
)

func NewNativeStreamDeckFactory(config StreamDeckConfig, brightness float64) StreamDeckFactory {
	return func(ctx context.Context) (StreamDeck, error) {
		return openNativeStreamDeck(ctx, config, brightness)
	}
}

func openNativeStreamDeck(ctx context.Context, config StreamDeckConfig, brightness float64) (StreamDeck, error) {
	device, err := openNativeDeck(ctx, config)
	if err != nil {
		return nil, err
	}
	if device == nil {
		return nil, errors.New("no supported StreamDeck found")
	}
	if device.Name != "Stream Deck MK.2" {
		_ = device.Close(context.Background())
		return nil, fmt.Errorf("unsupported StreamDeck model %q", device.Name)
	}
	if device.ButtonCount() != StreamDeckKeyCount {
		_ = device.Close(context.Background())
		return nil, fmt.Errorf("unsupported StreamDeck key count %d", device.ButtonCount())
	}
	// The pinned library starts a button-read goroutine from NewFromDevice and
	// its USB read has no bounded URB timeout. Keep that optional input loop
	// canceled so a faulty input endpoint cannot block the output display.
	inputCtx, cancelInput := context.WithCancel(context.Background())
	cancelInput()
	deck, err := decklib.NewFromDevice(inputCtx, device)
	if err != nil {
		_ = device.Close(context.Background())
		return nil, err
	}
	return newNativeStreamDeck(deck, brightness)
}

type nativeStreamDeck struct {
	deck   *decklib.StreamDeck
	events chan KeyEvent
}

func newNativeStreamDeck(deck *decklib.StreamDeck, brightness float64) (*nativeStreamDeck, error) {
	if deck == nil || deck.Device() == nil {
		return nil, errors.New("StreamDeck device is unavailable")
	}
	events := make(chan KeyEvent, 16)
	native := &nativeStreamDeck{deck: deck, events: events}
	deck.SetHandler(func(_ context.Context, index int) error {
		select {
		case events <- KeyEvent{Index: index}:
		default:
		}
		return nil
	})
	value := uint8(brightness * 100)
	if value == 0 {
		value = 1
	}
	if value > 100 {
		value = 100
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := deck.SetBrightness(ctx, value); err != nil {
		_ = deck.Close(context.Background())
		return nil, fmt.Errorf("set StreamDeck brightness: %w", err)
	}
	return native, nil
}

func (d *nativeStreamDeck) SetKey(ctx context.Context, index int, key KeyImage) error {
	if index < 0 || index >= StreamDeckKeyCount {
		return fmt.Errorf("invalid StreamDeck key index: %d", index)
	}
	if key.Image == nil {
		return errors.New("StreamDeck key image is missing")
	}
	data, err := d.deck.ProcessImage(key.Image)
	if err != nil {
		return err
	}
	return d.deck.Device().SetButton(ctx, index, data)
}

func (d *nativeStreamDeck) Clear(ctx context.Context) error {
	return d.deck.Device().Clear(ctx)
}

func (d *nativeStreamDeck) Events() <-chan KeyEvent { return d.events }

func (d *nativeStreamDeck) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return d.deck.Close(ctx)
}

var _ StreamDeck = (*nativeStreamDeck)(nil)
